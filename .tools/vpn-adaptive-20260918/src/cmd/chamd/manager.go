package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	randv2 "math/rand/v2"

	"chameleon/internal/chameleon"
)

// ServerEntry — нода, добавленная пользователем через панель.
type ServerEntry struct {
	Name   string `json:"name"`
	Addr   string `json:"addr"`
	PubKey string `json:"pubkey"` // публичный ключ ноды v2 (base64)
	// Опционально (Control Fabric): внешний bulletin-борд и общий seed для
	// чтения управляющих сообщений при обрыве (использует автопилот).
	CFBoardURL string `json:"cf_board_url,omitempty"`
	CFCarURL   string `json:"cf_car_url,omitempty"` // этап B2: CAR trigger-host ноды (fallback-канал при недоступном борде)
	CFSeed     string `json:"cf_seed,omitempty"`
	// CDN-фронтинг: если задан, клиент соединяется по WSS с фронтом
	// (Cloudflare Worker) вместо прямого TCP к Addr — для DPI destination IP
	// принадлежит CDN, IP ноды в трафике клиента не появляется.
	FrontURL string `json:"front_url,omitempty"`
}

// Store — JSON-хранилище списка серверов (data/servers.json).
type Store struct {
	path    string
	mu      sync.RWMutex
	Servers []ServerEntry `json:"servers"`
}

func LoadStore(path string) (*Store, error) {
	s := &Store{path: path}
	b, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(b, s); err != nil {
			return nil, fmt.Errorf("invalid server store %s: %w", path, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil // отсутствие файла — не ошибка
}

func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o600)
}

func (s *Store) Add(name, addr, pubkey string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if name == "" {
		name = addr
	}
	s.Servers = append(s.Servers, ServerEntry{Name: name, Addr: addr, PubKey: pubkey})
	index := len(s.Servers) - 1
	if err := s.saveLocked(); err != nil {
		s.Servers = s.Servers[:index]
		return 0, err
	}
	return index, nil
}

func (s *Store) Del(i int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if i < 0 || i >= len(s.Servers) {
		return fmt.Errorf("нет сервера с индексом %d", i)
	}
	removed := s.Servers[i]
	s.Servers = append(s.Servers[:i], s.Servers[i+1:]...)
	if err := s.saveLocked(); err != nil {
		s.Servers = append(s.Servers, ServerEntry{})
		copy(s.Servers[i+1:], s.Servers[i:])
		s.Servers[i] = removed
		return err
	}
	return nil
}

func (s *Store) List() []ServerEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]ServerEntry{}, s.Servers...)
}

// Manager — состояние клиентского демона: активное подключение,
// параметры туннеля, журнал событий для панели.
type Manager struct {
	store      *Store
	timeout    time.Duration
	cbr        time.Duration
	flavorName string
	clientKey  string // приватный ключ устройства (base64)
	clientPub  string // его публичная часть — для белого списка ноды

	// Хуки автоподхвата: TUN или системный прокси.
	onConnect    func()
	onDisconnect func()

	mu          sync.RWMutex
	activeAddr  string
	activeName  string
	activePub   string
	activeSince time.Time

	// Единственный сеанс "Хамелеон", мультиплексирующий все потоки.
	muxMu sync.Mutex
	mux   *chameleon.Mux
	strategyObserver func(chameleon.Flavor, string) func(chameleon.StrategyOutcome)
	cancelStrategyObservation func()

	// Счётчики трафика для индикации скорости в панели.
	upBytes   atomic.Uint64
	downBytes atomic.Uint64

	suspicious *SuspiciousLogger

	// Автопилот (добавочный слой; существующие настройки не меняются).
	dohMode       atomic.Bool       // резолв адресов нод через DoH (перехват DNS у провайдера)
	pinMap        map[string]string // DoH-пин: IP:port → исходный domain:port
	autoNote      atomic.Value      // string: последнее действие автопилота (для панели)
	genomeFlavor  *chameleon.Flavor // слой 8: одноразовый геном из θ (nil = обычный flavorName)
	onSessionDrop func()            // хук «сеанс умер» (зовётся асинхронно)
	onSessionUp   func()            // хук «сеанс поднят» (зовётся асинхронно; слой 3: выжившие канарейки)

	// Реестр фактических адресов слушателей (раунд 6: кастомные порты).
	listenMu    sync.Mutex
	listenAddrs map[string]string

	logMu sync.Mutex
	logs  []string
}

func NewManager(store *Store, timeout, cbr time.Duration, flavorName, clientKey string, suspicious *SuspiciousLogger) *Manager {
	pub := ""
	if priv, err := chameleon.ParseNodePrivKey(clientKey); err == nil {
		pub = pubKeyOf(priv)
	}
	return &Manager{
		store:      store,
		timeout:    timeout,
		cbr:        cbr,
		flavorName: flavorName,
		clientKey:  clientKey,
		clientPub:  pub,
		suspicious: suspicious,
		pinMap:      make(map[string]string),
		listenAddrs: make(map[string]string),
	}
}

func (m *Manager) SetHooks(onConnect, onDisconnect func()) {
	m.onConnect, m.onDisconnect = onConnect, onDisconnect
}

// --- Автопилот: хуки и переключатели (добавочный слой) ---

// SetDoHMode включает/выключает резолв адресов нод через DoH.
func (m *Manager) SetDoHMode(on bool) { m.dohMode.Store(on) }

// DoHMode — текущее состояние DoH-режима (для панели).
func (m *Manager) DoHMode() bool { return m.dohMode.Load() }

// SetAutoNote записывает последнее действие автопилота (для панели).
func (m *Manager) SetAutoNote(note string) { m.autoNote.Store(note) }

// SetOnSessionDrop регистрирует колбэк на смерть сеанса (автопилот).
func (m *Manager) SetOnSessionDrop(fn func()) { m.onSessionDrop = fn }

// SetOnSessionUp регистрирует колбэк на успешный подъём сеанса (автопилот).
func (m *Manager) SetOnSessionUp(fn func()) { m.onSessionUp = fn }

// SetListenAddr запоминает фактический адрес слушателя: порт мог быть
// подобран автоматически (раунд 6) — панель показывает, куда реально встали
// SOCKS5/панель/DNS.
func (m *Manager) SetListenAddr(name, addr string) {
	m.listenMu.Lock()
	defer m.listenMu.Unlock()
	m.listenAddrs[name] = addr
}

// dialAddr резолвит адрес ноды для дозвона. В DoH-режиме (автопилот подтвердил
// перехват plain-DNS провайдером) домен резолвится через DoH, а не системный
// DNS; пин IP→домен запоминается, чтобы учёт активной ноды шёл по домену.
func (m *Manager) dialAddr(addr string) string {
	if !m.dohMode.Load() {
		return addr
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || net.ParseIP(strings.Trim(host, "[]")) != nil {
		return addr
	}
	r := chameleon.NewDoHResolver("")
	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()
	ips, err := r.ResolveA(ctx, host)
	if err != nil || len(ips) == 0 {
		m.logf("autopilot: DoH-резолв %s не удался (%v) — пробую системный DNS", host, err)
		return addr
	}
	pinned := net.JoinHostPort(ips[randv2.IntN(len(ips))], port)
	m.mu.Lock()
	m.pinMap[pinned] = addr
	m.mu.Unlock()
	m.logf("autopilot: %s → %s через DoH (обход перехвата DNS)", addr, pinned)
	return pinned
}

// dialServer выбирает несущий транспорт записи ноды: front_url (CDN-фронтинг
// через WSS — для DPI destination IP принадлежит CDN, не ноде) или прямой TCP.
func (m *Manager) dialServer(srv ServerEntry) (*chameleon.Conn, error) {
	if srv.FrontURL == "" {
		return chameleon.DialNode(m.dialAddr(srv.Addr), srv.PubKey, m.clientKey, m.timeout)
	}
	pub, err := chameleon.ParseNodePubKey(srv.PubKey)
	if err != nil {
		return nil, err
	}
	priv, err := chameleon.ParseNodePrivKey(m.clientKey)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.timeout+15*time.Second)
	defer cancel()
	raw, err := chameleon.DialWS(ctx, srv.FrontURL, m.frontPinIP(srv.FrontURL), nil)
	if err != nil {
		return nil, err
	}
	sess, err := chameleon.ClientHandshake(raw, pub, priv)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("handshake через фронт: %w", err)
	}
	return chameleon.NewClientConn(raw, sess)
}

// frontPinIP: при включённом DoH-режиме (автопилот подтвердил перехват DNS)
// резолвит хост фронта через DoH и возвращает IP для прямого дозвона — SNI и
// Host остаются исходными. Пустая строка = обычный системный резолв.
func (m *Manager) frontPinIP(frontURL string) string {
	if !m.dohMode.Load() {
		return ""
	}
	u, err := url.Parse(frontURL)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	if host == "" || net.ParseIP(host) != nil {
		return ""
	}
	r := chameleon.NewDoHResolver("")
	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()
	ips, err := r.ResolveA(ctx, host)
	if err != nil || len(ips) == 0 {
		m.logf("autopilot: DoH-резолв фронта %s не удался (%v) — системный DNS", host, err)
		return ""
	}
	ip := ips[randv2.IntN(len(ips))]
	m.logf("autopilot: фронт %s → %s через DoH", host, ip)
	return ip
}

// RotateFlavor переключает маску ритма CBR на следующую из списка и возвращает
// её имя. Применяется автопилотом при RST/SNI-интерференции.
func (m *Manager) RotateFlavor() string {
	names := make([]string, 0, len(chameleon.Flavors))
	for name := range chameleon.Flavors {
		names = append(names, name)
	}
	sort.Strings(names)
	m.mu.Lock()
	defer m.mu.Unlock()
	next := names[0]
	for i, n := range names {
		if n == m.flavorName {
			next = names[(i+1)%len(names)]
			break
		}
	}
	m.flavorName = next
	m.genomeFlavor = nil // ручная/legacy ротация отменяет θ-геном
	return next
}

// SetGenomeFlavor применяет одноразовый геном, выведенный из θ-распределения
// (слой 8): следующий сеанс стартует с этими параметрами ритма.
func (m *Manager) SetGenomeFlavor(f chameleon.Flavor) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.genomeFlavor = &f
}

// ForceReconnect рвёт текущий сеанс: следующий openStream переподключается уже
// с новыми параметрами (flavor, DoH-пин). Вызывается автопилотом.
func (m *Manager) ForceReconnect(reason string) {
	m.muxMu.Lock()
	m.cancelStrategyObservationLocked()
	if m.mux != nil {
		m.mux.Conn().Close()
		m.mux = nil
	}
	m.muxMu.Unlock()
	m.logf("autopilot: реконнект (%s)", reason)
}

// ActiveServerEntry возвращает запись активной ноды (для автопилота). DoH-пины
// раскрываются обратно в исходный домен.
func (m *Manager) ActiveServerEntry() (ServerEntry, bool) {
	m.mu.RLock()
	addr := m.activeAddr
	if orig, ok := m.pinMap[addr]; ok {
		addr = orig
	}
	m.mu.RUnlock()
	for _, s := range m.store.List() {
		if s.Addr == addr {
			return s, true
		}
	}
	return ServerEntry{}, false
}

// ClientPubBytes — публичный ключ устройства в байтах (для ControlSessionID).
func (m *Manager) ClientPubBytes() []byte {
	b, err := base64.RawURLEncoding.DecodeString(m.clientPub)
	if err != nil {
		return nil
	}
	return b
}

// flavor возвращает flavor текущего сеанса; "auto" — случайный RU-сервис.
// Если автопилот применил θ-геном (слой 8), он имеет приоритет над списком.
func (m *Manager) flavor() chameleon.Flavor {
	m.mu.RLock()
	name := m.flavorName
	g := m.genomeFlavor
	m.mu.RUnlock()
	if g != nil {
		return *g
	}
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err == nil {
		return chameleon.FlavorByName(name, chameleon.NewDRBG(seed[:], "flavor"))
	}
	return chameleon.FlavorByName(name, nil)
}

func (m *Manager) logf(format string, args ...any) {
	m.logMu.Lock()
	defer m.logMu.Unlock()
	line := time.Now().Format("15:04:05") + "  " + fmt.Sprintf(format, args...)
	m.logs = append(m.logs, line)
	if len(m.logs) > 200 {
		m.logs = m.logs[len(m.logs)-200:]
	}
}

func (m *Manager) Logs() []string {
	m.logMu.Lock()
	defer m.logMu.Unlock()
	return append([]string{}, m.logs...)
}

// Connect выбирает ноду и проверяет её рукопожатием.
func (m *Manager) Connect(i int) error {
	servers := m.store.List()
	if i < 0 || i >= len(servers) {
		return fmt.Errorf("нет сервера с индексом %d", i)
	}
	srv := servers[i]
	if srv.PubKey == "" {
		err := fmt.Errorf("у сервера %s нет публичного ключа — удалите и добавьте заново с ключом ноды", srv.Name)
		m.logf("ошибка: %v", err)
		return err
	}
	m.logf("подключение к %s (%s)...", srv.Name, srv.Addr)
	conn, err := m.dialServer(srv)
	if err != nil {
		m.logf("ошибка: %v", err)
		return err
	}
	// Один сеанс на всё: мультиплексируем потоки, рукопожатие платится один раз.
	m.muxMu.Lock()
	m.cancelStrategyObservationLocked()
	if m.mux != nil {
		m.mux.Conn().Close()
	}
	m.mux = chameleon.NewMuxClient(conn)
	if m.cbr > 0 {
		f := m.flavor()
		m.mux.Conn().StartShaper(f.Base, f.Jitter, f.MinPad, f.MaxPad, "c2s-cbr")
		m.startStrategyObservationLocked(m.mux, f, srv.PubKey)
	}
	m.muxMu.Unlock()
	m.mu.Lock()
	m.activeAddr, m.activeName, m.activePub, m.activeSince = srv.Addr, srv.Name, srv.PubKey, time.Now()
	m.upBytes.Store(0)
	m.downBytes.Store(0)
	m.mu.Unlock()
	m.logf("подключено: %s. Сеанс мультиплексирует все потоки.", srv.Name)
	if m.onConnect != nil {
		m.onConnect()
	}
	if m.onSessionUp != nil {
		go m.onSessionUp() // слой 3: канарейка дожила до сеанса
	}
	return nil
}

func (m *Manager) Disconnect() {
	m.muxMu.Lock()
	m.cancelStrategyObservationLocked()
	if m.mux != nil {
		m.mux.Conn().Close()
		m.mux = nil
	}
	m.muxMu.Unlock()
	m.mu.Lock()
	name := m.activeName
	m.activeAddr, m.activeName, m.activePub = "", "", ""
	m.activeSince = time.Time{}
	m.mu.Unlock()
	if name != "" {
		m.logf("отключено от %s", name)
		if m.onDisconnect != nil {
			m.onDisconnect()
		}
	}
}

type Status struct {
	Active     bool              `json:"active"`
	Name       string            `json:"name"`
	Addr       string            `json:"addr"`
	Since      string            `json:"since,omitempty"`
	CBR        string            `json:"cbr"`
	ClientPub  string            `json:"client_pubkey"`
	Pool       []ServerEntry     `json:"servers"`
	Logs       []string          `json:"logs"`
	RTTms      int64             `json:"rtt_ms"`     // пинг до ноды (по keepalive мультиплексора)
	UpBytes    uint64            `json:"up_bytes"`   // всего отправлено через туннель
	DownBytes  uint64            `json:"down_bytes"` // всего получено
	Suspicious []SuspiciousEvent `json:"suspicious"`
	// Автопилот:
	DoHMode  bool   `json:"doh_mode"`            // резолв нод через DoH (перехват DNS)
	AutoNote string `json:"auto_note,omitempty"` // последнее действие автопилота
	// Фактические адреса слушателей (раунд 6: порт мог быть подобран автоматически):
	Listen map[string]string `json:"listen,omitempty"`
}

func (m *Manager) Status() Status {
	var susp []SuspiciousEvent
	if m.suspicious != nil {
		susp = m.suspicious.Events()
	}
	m.mu.RLock()
	st := Status{
		Active:     m.activeAddr != "",
		Name:       m.activeName,
		Addr:       m.activeAddr,
		CBR:        m.cbr.String(),
		ClientPub:  m.clientPub,
		Pool:       m.store.List(),
		Logs:       m.Logs(),
		UpBytes:    m.upBytes.Load(),
		DownBytes:  m.downBytes.Load(),
		Suspicious: susp,
		DoHMode:    m.dohMode.Load(),
	}
	if v := m.autoNote.Load(); v != nil {
		st.AutoNote, _ = v.(string)
	}
	m.listenMu.Lock()
	if len(m.listenAddrs) > 0 {
		st.Listen = make(map[string]string, len(m.listenAddrs))
		for k, v := range m.listenAddrs {
			st.Listen[k] = v
		}
	}
	m.listenMu.Unlock()
	if st.Active {
		st.Since = m.activeSince.Format("15:04:05")
	}
	m.mu.RUnlock()
	m.muxMu.Lock()
	mx := m.mux
	m.muxMu.Unlock()
	if st.Active && mx != nil && mx.Alive() {
		st.RTTms = mx.RTT().Milliseconds()
	}
	return st
}

// openStream открывает поток к цели через мультиплексированный сеанс.
func (m *Manager) openStream(target string) (*chameleon.Stream, error) {
	if m.suspicious != nil {
		m.suspicious.InspectTarget(target, "socks5-client")
	}
	mx, err := m.ensureMux()
	if err != nil {
		return nil, err
	}
	return mx.Open(target)
}

// ensureMux возвращает живой мультиплексор, при смерти сеанса —
// переподключается: сначала активная нода, при сбое — весь пул.
func (m *Manager) ensureMux() (*chameleon.Mux, error) {
	m.mu.RLock()
	active := m.activeAddr
	activePub := m.activePub
	m.mu.RUnlock()
	if active == "" {
		return nil, fmt.Errorf("нет активного подключения — выберите сервер в панели")
	}

	m.muxMu.Lock()
	mx := m.mux
	if mx != nil && !mx.Alive() {
		// Its monitor must retain the peer failure, not turn it into cancellation.
		m.cancelStrategyObservation = nil
		m.logf("сеанс умер (%v), переподключение...", mx.Err())
		mx.Conn().Close()
		m.mux = nil
		mx = nil
		if m.onSessionDrop != nil {
			go m.onSessionDrop() // автопилот реагирует асинхронно, без muxMu
		}
	}
	if mx == nil {
		conn, err := chameleon.DialNode(m.dialAddr(active), activePub, m.clientKey, m.timeout)
		if err != nil {
			m.logf("активная нода %s не отвечает (%v), failover по пулу...", active, err)
			var rest []chameleon.Node
			for _, s := range m.store.List() {
				if s.Addr != active && s.PubKey != "" {
					rest = append(rest, chameleon.Node{Name: s.Name, Addr: m.dialAddr(s.Addr), PubKey: s.PubKey})
				}
			}
			if len(rest) > 0 {
				var addr string
				conn, addr, err = chameleon.DialPool(rest, m.clientKey, m.timeout)
				if err == nil {
					m.logf("failover: сеанс через %s", addr)
					for _, n := range rest {
						if n.Addr == addr {
							m.mu.Lock()
							activePub = n.PubKey
							m.activeAddr, m.activeName, m.activePub = n.Addr, n.Name, n.PubKey
							m.mu.Unlock()
						}
					}
				}
			}
			if err != nil {
				m.muxMu.Unlock()
				return nil, err
			}
		}
		mx = chameleon.NewMuxClient(conn)
		if m.cbr > 0 {
			f := m.flavor()
			mx.Conn().StartShaper(f.Base, f.Jitter, f.MinPad, f.MaxPad, "c2s-cbr")
			m.startStrategyObservationLocked(mx, f, activePub)
		}
		m.mux = mx
		if m.onSessionUp != nil {
			go m.onSessionUp() // слой 3: канарейка дожила до сеанса (реконнект)
		}
	}
	m.muxMu.Unlock()

	return mx, nil
}

// openUDPStream открывает UDP-релей к цели (DNS, QUIC и пр.).
func (m *Manager) openUDPStream(target string) (*chameleon.Stream, error) {
	mx, err := m.ensureMux()
	if err != nil {
		return nil, err
	}
	return mx.OpenUDP(target)
}

// loadOrCreateClientKey загружает персональный ключ устройства из файла
// или генерирует новый. Возвращает приватный и публичный ключи (base64).
func loadOrCreateClientKey(path string) (privB64, pubB64 string, err error) {
	if priv, err := chameleon.LoadNodeKey(path); err == nil {
		return strings.TrimSpace(mustRead(path)), pubKeyOf(priv), nil
	}
	privB64, pubB64, err = chameleon.GenerateNodeKey()
	if err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", "", err
	}
	if err := chameleon.SaveNodeKey(path, privB64); err != nil {
		return "", "", err
	}
	return privB64, pubB64, nil
}

func mustRead(path string) string {
	b, _ := os.ReadFile(path)
	return string(b)
}

func pubKeyOf(priv *ecdh.PrivateKey) string {
	return base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())
}
