package chameleon

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Мультиплексор: все потоки данных идут через ОДИН сеанс "Хамелеон".
//
// Без мультиплексирования каждое TCP-подключение платило полный RTT
// рукопожатия до ноды — на сайтах с десятками соединений это убивало
// скорость. Теперь рукопожатие одно, потоки мультиплексируются кадрами:
//
//	[streamID uint32][cmd byte][payload]
//
// Команды: open (с ATYP-целью), openOK/openErr, data, close, ping/pong,
// resolve/resolveOK/resolveErr, openAuth.
// Побочный плюс для маскировки: снаружи одно долгоживущее соединение
// с равномерным ритмом — похоже на HTTP/2 или видеозвонок, а не на
// рой коротких подключений.
const (
	smOpen       = 0x01
	smOpenOK     = 0x02
	smOpenErr    = 0x03
	smData       = 0x04
	smClose      = 0x05
	smPing       = 0x06 // keepalive: payload = 8 байт unixnano, ответ — smPong с тем же payload
	smPong       = 0x07
	smResolve    = 0x08 // клиент → нода: домен для резолва
	smResolveOK  = 0x09 // нода → клиент: ResolutionObject
	smResolveErr = 0x0A // нода → клиент: ошибка резолва
	smOpenAuth   = 0x0B // клиент → нода: open с ResolutionObject (защита от rebinding)
	smCITPObject = 0x0C // пересылка типизированных CITP объектов
	smResume     = 0x0D // восстановление потока с MigrationTicket / offset reconciliation
	smResumeOK   = 0x0E // подтверждение возобновления
	smResumeErr  = 0x0F // отказ в возобновлении

	muxHeader           = 5
	muxMaxData          = 60000
	openTimout          = 15 * time.Second
	streamQueueDepth    = 16
	defaultMaxStreams   = 256
	maxPendingHandlers  = 64
	maxResolutionCache  = 256
	maxOpenPayloadBytes = 2048
	maxErrorPayload     = 512

	pingInterval = 5 * time.Second
)

// Stream — один мультиплексированный поток. Реализует net.Conn-подобный
// интерфейс (Read/Write/Close).
type Stream struct {
	m    *Mux
	id   uint32
	inCh chan []byte

	mu        sync.Mutex
	buf       []byte
	closed    bool
	openErr   error
	openDone  chan error
	closeOnce sync.Once
	inOnce    sync.Once
	lifetime  *time.Timer
}

func (s *Stream) ID() uint32 { return s.id }

func (s *Stream) closeInput() { s.inOnce.Do(func() { close(s.inCh) }) }

func (s *Stream) feed(p []byte) (accepted bool) {
	// A slow stream must not block the single mux read loop indefinitely.
	// The queue is bounded; overflow closes only the offending stream.
	defer func() { _ = recover() }()
	payload := append([]byte(nil), p...)
	select {
	case s.inCh <- payload:
		return true
	default:
		_ = s.m.send(s.id, smClose, nil)
		s.m.remove(s.id)
		return false
	}
}

func (s *Stream) Read(p []byte) (int, error) {
	s.mu.Lock()
	if len(s.buf) > 0 {
		n := copy(p, s.buf)
		s.buf = s.buf[n:]
		s.mu.Unlock()
		s.m.payloadReceived.Add(uint64(n))
		return n, nil
	}
	s.mu.Unlock()

	b, ok := <-s.inCh
	if !ok {
		return 0, io.EOF
	}
	n := copy(p, b)
	if n < len(b) {
		s.mu.Lock()
		s.buf = b[n:]
		s.mu.Unlock()
	}
	s.m.payloadReceived.Add(uint64(n))
	return n, nil
}

func (s *Stream) Write(p []byte) (int, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	s.mu.Unlock()
	total := 0
	for total < len(p) {
		n := min(len(p)-total, muxMaxData)
		if err := s.m.send(s.id, smData, p[total:total+n]); err != nil {
			return total, err
		}
		total += n
		s.m.payloadSent.Add(uint64(n))
		s.m.conn.noteUsefulPayload(n)
	}
	return total, nil
}

func (s *Stream) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		s.m.send(s.id, smClose, nil)
		s.m.remove(s.id)
	})
	return nil
}

// Mux — мультиплексор поверх одного *Conn.
type Mux struct {
	conn *Conn
	payloadSent atomic.Uint64
	payloadReceived atomic.Uint64
	issuedResolutions resolutionIssuance

	mu      sync.Mutex
	streams map[uint32]*Stream
	nextID  uint32
	alive   bool
	lastErr error

	rtt atomic.Int64 // последний измеренный RTT, наносекунды (клиентская сторона)

	// Клиентский кэш DNS-binding: домен → подписанный нодой объект,
	// чтобы не платить лишний RESOLVE-RTT на каждое соединение.
	resMu    sync.Mutex
	resCache map[string]*ResolutionObject

	onOpen     func(m *Mux, sid uint32, target []byte)  // только на сервере
	onResolve  func(m *Mux, sid uint32, domain string)  // только на сервере
	onOpenAuth func(m *Mux, sid uint32, payload []byte) // только на сервере
	onCITP     func(m *Mux, obj *CITPObject)            // обработчик CITP объектов
	onResume   func(m *Mux, sid uint32, payload []byte) // обработчик smResume

	policy         *PolicyEngine
	maxStreams     int
	streamLifetime time.Duration
	handlerSem     chan struct{}

	// Каскад нода→нода: когда egress задан, TCP/UDP egress-потоки уходят через
	// вышестоящую ноду, а локальный RESOLVE отключён (домены резолвит выход).
	egress          func(hostport string) (net.Conn, error)
	egressUDP       func(hostport string) (net.Conn, error)
	resolveDisabled bool
}

func newMux(conn *Conn) *Mux {
	return &Mux{
		conn:       conn,
		streams:    make(map[uint32]*Stream),
		alive:      true,
		resCache:   make(map[string]*ResolutionObject),
		maxStreams: defaultMaxStreams,
		handlerSem: make(chan struct{}, maxPendingHandlers),
	}
}

// NewMuxClient — клиентская сторона: запускает read-цикл и keepalive-пинг
// (раз в 5 секунд, RTT доступен через RTT()).
func NewMuxClient(conn *Conn) *Mux {
	m := newMux(conn)
	m.nextID = 1
	go m.loop()
	go m.keepalive()
	return m
}

// RTT — последний измеренный пинг до ноды (0 — ещё не измерен).
func (m *Mux) RTT() time.Duration { return time.Duration(m.rtt.Load()) }

// keepalive шлёт smPing с текущим временем; нода отвечает smPong с тем же
// payload, и RTT вычисляется по разнице. Заодно это удерживает NAT-маппинги
// и не даёт ТСПУ/файрволам убить «молчащее» соединение.
func (m *Mux) keepalive() {
	t := time.NewTicker(pingInterval)
	defer t.Stop()
	for range t.C {
		if !m.Alive() {
			return
		}
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(time.Now().UnixNano()))
		if err := m.send(0, smPing, b[:]); err != nil {
			return
		}
	}
}

func (m *Mux) Conn() *Conn { return m.conn }

func (m *Mux) PayloadStats() (sent, received uint64) {
	return m.payloadSent.Load(), m.payloadReceived.Load()
}

var errResolveViaUpstream = errors.New("resolve: отключён на входной ноде каскада")

func (m *Mux) Alive() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.alive
}

func (m *Mux) Err() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastErr
}

func (m *Mux) send(sid uint32, cmd byte, payload []byte) error {
	f := make([]byte, muxHeader+len(payload))
	binary.BigEndian.PutUint32(f, sid)
	f[4] = cmd
	copy(f[muxHeader:], payload)
	return m.conn.WriteMessage(f)
}

func (m *Mux) putStream(s *Stream) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.alive {
		return errors.New("mux closed")
	}
	if _, exists := m.streams[s.id]; exists {
		return errors.New("duplicate stream id")
	}
	if len(m.streams) >= m.maxStreams {
		return errors.New("stream limit reached")
	}
	m.streams[s.id] = s
	if m.streamLifetime > 0 {
		s.lifetime = time.AfterFunc(m.streamLifetime, func() {
			_ = m.send(s.id, smClose, nil)
			m.remove(s.id)
		})
	}
	return nil
}

func boundedText(err error) []byte {
	if err == nil {
		return nil
	}
	b := []byte(err.Error())
	if len(b) > maxErrorPayload {
		b = b[:maxErrorPayload]
	}
	return b
}

func (m *Mux) dispatch(sid uint32, errorCmd byte, fn func()) {
	select {
	case m.handlerSem <- struct{}{}:
		go func() {
			defer func() { <-m.handlerSem }()
			fn()
		}()
	default:
		_ = m.send(sid, errorCmd, []byte("server busy"))
	}
}

func (m *Mux) authorizeOpen(hostport string) error {
	if m.policy == nil {
		return nil
	}
	// Каскад: доменная цель без ResolutionObject легальна — её резолвит и
	// проверяет своей политикой выходная нода. IP-цели проверяются полностью.
	if m.resolveDisabled {
		if host, _, err := net.SplitHostPort(hostport); err == nil && net.ParseIP(strings.Trim(host, "[]")) == nil {
			if decision, reason := m.policy.EvaluateOpenAllowingUnresolvedDomain(hostport); decision != PolicyAllow {
				return fmt.Errorf("policy %s: %s", decision, reason)
			}
			return nil
		}
	}
	decision, reason := m.policy.EvaluateOpen(hostport)
	if decision != PolicyAllow {
		return fmt.Errorf("policy %s: %s", decision, reason)
	}
	return nil
}

func (m *Mux) cacheResolution(domain string, ro *ResolutionObject) {
	m.resMu.Lock()
	defer m.resMu.Unlock()
	if len(m.resCache) >= maxResolutionCache {
		now := time.Now().Unix()
		for key, cached := range m.resCache {
			if cached == nil || cached.Expiry <= now {
				delete(m.resCache, key)
			}
		}
	}
	if len(m.resCache) >= maxResolutionCache {
		for key := range m.resCache {
			delete(m.resCache, key)
			break
		}
	}
	m.resCache[domain] = ro
}

func (m *Mux) get(sid uint32) *Stream {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.streams[sid]
}

func (m *Mux) remove(sid uint32) {
	m.mu.Lock()
	if s, ok := m.streams[sid]; ok {
		delete(m.streams, sid)
		if s.lifetime != nil {
			s.lifetime.Stop()
		}
		s.closeInput()
	}
	m.mu.Unlock()
}

func (m *Mux) kill(err error) {
	m.mu.Lock()
	if !m.alive {
		m.mu.Unlock()
		return
	}
	m.alive = false
	m.lastErr = err
	ss := make([]*Stream, 0, len(m.streams))
	for _, s := range m.streams {
		ss = append(ss, s)
	}
	m.streams = make(map[uint32]*Stream)
	m.mu.Unlock()
	if m.conn != nil { _ = m.conn.Close() }
	for _, s := range ss {
		s.closeInput()
		s.mu.Lock()
		s.closed = true
		if s.openDone != nil {
			select {
			case s.openDone <- fmt.Errorf("сеанс умер: %w", err):
			default:
			}
		}
		s.mu.Unlock()
	}
}

func (m *Mux) loop() {
	for {
		f, err := m.conn.ReadMessage() // кадры-паддинги пропускаются внутри
		if err != nil {
			m.kill(err)
			return
		}
		if len(f) < muxHeader {
			continue
		}
		sid := binary.BigEndian.Uint32(f)
		cmd := f[4]
		payload := f[muxHeader:]
		switch cmd {
		case smOpen:
			if m.onOpen != nil {
				p := append([]byte(nil), payload...)
				m.dispatch(sid, smOpenErr, func() { m.onOpen(m, sid, p) })
			}
		case smData:
			if s := m.get(sid); s != nil {
				s.feed(payload)
			}
		case smClose:
			m.remove(sid)
		case smOpenOK, smOpenErr, smResolveOK, smResolveErr:
			if s := m.get(sid); s != nil && s.openDone != nil {
				var e error
				if cmd == smOpenErr || cmd == smResolveErr {
					e = errors.New(string(payload))
					if cmd == smResolveErr && string(payload) == errResolveViaUpstream.Error() { e = errResolveViaUpstream }
				}
				if cmd == smResolveOK && e == nil && len(payload) > 0 {
					// ResolutionObject едет в payload этого же кадра —
					// передаём его ждущему Resolve() через очередь потока.
					s.feed(payload)
				}
				select {
				case s.openDone <- e:
				default:
				}
			}
		case smResolve:
			if m.onResolve != nil {
				domain := string(payload)
				m.dispatch(sid, smResolveErr, func() { m.onResolve(m, sid, domain) })
			}
		case smOpenAuth:
			if m.onOpenAuth != nil {
				p := append([]byte(nil), payload...)
				m.dispatch(sid, smOpenErr, func() { m.onOpenAuth(m, sid, p) })
			}
		case smCITPObject:
			if obj, err := DecodeCITPObject(payload); err == nil {
				if obj.IsExpired(time.Now().UnixMilli()) {
					continue
				}
				if obj.Verify(m.conn.seed) {
					if m.onCITP != nil {
						objCopy := obj
						m.dispatch(obj.StreamID, smClose, func() { m.onCITP(m, objCopy) })
					}
					// Если это чанк потока, направляем в соответствующий Stream
					if obj.Type == ObjTypeStreamChunk {
						if s := m.get(obj.StreamID); s != nil {
							s.feed(obj.Payload)
						}
					}
				}
			}
		case smResume:
			if m.onResume != nil {
				p := append([]byte(nil), payload...)
				m.dispatch(sid, smResumeErr, func() { m.onResume(m, sid, p) })
			}
		case smResumeOK, smResumeErr:
			if s := m.get(sid); s != nil && s.openDone != nil {
				var e error
				if cmd == smResumeErr {
					e = errors.New(string(payload))
				}
				select {
				case s.openDone <- e:
				default:
				}
			}
		case smPing: // keepalive — отвечаем эхом (нужно только серверу, но безвредно везде)
			m.send(sid, smPong, payload)
		case smPong:
			if len(payload) == 8 {
				sent := int64(binary.BigEndian.Uint64(payload))
				if d := time.Since(time.Unix(0, sent)); d >= 0 {
					m.rtt.Store(d.Nanoseconds())
				}
			}
		}
	}
}

// udpTargetMarker — первый байт target для UDP-релея (датаграммы поверх
// потока с 2-байтным префиксом длины). Остальное — "host:port" в ASCII.
const udpTargetMarker = 0xF0

// EncodeUDPTarget кодирует цель UDP-релея.
func EncodeUDPTarget(hostport string) []byte {
	return append([]byte{udpTargetMarker}, []byte(hostport)...)
}

// OpenUDP открывает UDP-релей к цели: каждая датаграмма на Stream
// обрамляется 2-байтным префиксом длины (big-endian).
func (m *Mux) OpenUDP(hostport string) (*Stream, error) {
	return m.OpenRaw(EncodeUDPTarget(hostport))
}

// Open открывает поток к цели (ATYP-адрес "host:port") — клиентская сторона.
// Если цель — домен, используется DNS-binding (Фаза 1 CITP): RESOLVE у ноды
// (с кэшем до конца TTL) + OPEN с подписанным объектом. Нода подключается
// только к адресам из собственного доверенного ответа — rebinding и подмена
// домена исключены. Delegation to an upstream is accepted only through an
// explicit authenticated response; timeout/auth/policy errors never downgrade.
func (m *Mux) Open(hostport string) (*Stream, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip == nil {
		// Домен: сначала кэш resolution (без лишнего RTT), иначе свежий RESOLVE.
		domain := strings.ToLower(strings.TrimSuffix(host, "."))
		m.resMu.Lock()
		ro := m.resCache[domain]
		m.resMu.Unlock()
		if ro == nil || time.Now().Unix() >= ro.Expiry-30 {
			fresh, resolveErr := m.Resolve(domain)
			if resolveErr != nil {
				if !errors.Is(resolveErr, errResolveViaUpstream) { return nil, fmt.Errorf("DNS binding: %w", resolveErr) }
				encoded, err := EncodeTarget(hostport)
				if err != nil { return nil, err }
				return m.OpenRaw(encoded)
			}
			ro = fresh
			m.cacheResolution(domain, ro)
		}
		stream, _, openErr := m.openBoundWithObject(ro, port)
		if openErr != nil {
			m.resMu.Lock()
			delete(m.resCache, domain)
			m.resMu.Unlock()
			return nil, openErr
		}
		return stream, nil
	}
	enc, err := EncodeTarget(hostport)
	if err != nil {
		return nil, err
	}
	return m.OpenRaw(enc)
}

// openBoundWithObject — OPEN с уже готовым ResolutionObject (без RESOLVE).
func (m *Mux) openBoundWithObject(ro *ResolutionObject, port string) (*Stream, *ResolutionObject, error) {
	var lastErr error
	for _, addr := range ro.Addrs {
		enc, err := EncodeTarget(net.JoinHostPort(addr, port))
		if err != nil {
			lastErr = err
			continue
		}
		roB := ro.Encode()
		payload := make([]byte, 0, 2+len(roB)+len(enc))
		payload = binary.BigEndian.AppendUint16(payload, uint16(len(roB)))
		payload = append(payload, roB...)
		payload = append(payload, enc...)
		st, err := m.openRawAuth(payload)
		if err != nil {
			lastErr = err
			continue
		}
		return st, ro, nil
	}
	if lastErr != nil {
		return nil, nil, lastErr
	}
	return nil, nil, fmt.Errorf("no address resolved for %s", ro.Domain)
}

// OpenWithResolve открывает поток к домену через связку RESOLVE→OPEN.
// Нода сама резолвит домен, возвращает ResolutionObject, и клиент шлёт
// open с подтверждённым объектом — защита от DNS rebinding.
// Проводной формат smOpenAuth: [u16 roLen][ro][ATYP-цель].
func (m *Mux) OpenWithResolve(domain, port string) (*Stream, *ResolutionObject, error) {
	ro, err := m.Resolve(domain)
	if err != nil {
		return nil, nil, err
	}
	return m.openBoundWithObject(ro, port)
}

// Resolve запрашивает у ноды ResolutionObject для домена.
func (m *Mux) Resolve(domain string) (*ResolutionObject, error) {
	if !m.Alive() {
		return nil, m.Err()
	}
	m.mu.Lock()
	sid := m.nextID
	m.nextID++
	m.mu.Unlock()
	s := &Stream{m: m, id: sid, inCh: make(chan []byte, streamQueueDepth), openDone: make(chan error, 1)}
	if err := m.putStream(s); err != nil {
		return nil, err
	}

	if err := m.send(sid, smResolve, []byte(domain)); err != nil {
		m.remove(sid)
		return nil, err
	}
	select {
	case err := <-s.openDone:
		if err != nil {
			m.remove(sid)
			return nil, err
		}
		// openDone сигнализирует успех, данные ResolutionObject — в inCh
		select {
		case data := <-s.inCh:
			ro, derr := DecodeResolutionObject(data)
			m.remove(sid) // resolve не создаёт долгоживущий поток
			if derr != nil {
				return nil, derr
			}
			if verr := ro.Verify(m.conn.seed); verr != nil {
				return nil, verr
			}
			if !strings.EqualFold(strings.TrimSuffix(domain, "."), ro.Domain) {
				return nil, errors.New("resolution domain does not match request")
			}
			return ro, nil
		case <-time.After(openTimout):
			m.remove(sid)
			return nil, fmt.Errorf("таймаут получения ResolutionObject")
		}
	case <-time.After(openTimout):
		m.remove(sid)
		return nil, fmt.Errorf("таймаут резолва")
	}
}

// SendCITPObject отправляет подписанный CITP-объект в сессию.
func (m *Mux) SendCITPObject(obj *CITPObject) error {
	if obj == nil { return errors.New("citp: nil object") }
	if !m.Alive() {
		return m.Err()
	}
	obj.Sign(m.conn.seed)
	encoded := obj.Encode()
	if encoded == nil {
		return errors.New("citp: object cannot be encoded")
	}
	frame := make([]byte, muxHeader+len(encoded))
	binary.BigEndian.PutUint32(frame, obj.StreamID)
	frame[4] = smCITPObject
	copy(frame[muxHeader:], encoded)
	if err := m.conn.writeSemanticMessage(frame, obj); err != nil { return err }
	if obj.Type == ObjTypeStreamChunk || obj.Type == ObjTypeDatagramBatch {
		m.payloadSent.Add(uint64(len(obj.Payload)))
		m.conn.noteUsefulPayload(len(obj.Payload))
	}
	return nil
}

// SetOnCITP регистрирует обработчик входящих CITP-объектов.
func (m *Mux) SetOnCITP(fn func(m *Mux, obj *CITPObject)) {
	m.onCITP = fn
}

// ResumeStream запрашивает возобновление сессии/потока по тикету миграции.
func (m *Mux) ResumeStream(ticket *MigrationTicket) error {
	if !m.Alive() {
		return m.Err()
	}
	ticket.Sign(m.conn.seed)

	sid := ticket.StreamID
	m.mu.Lock()
	s := m.streams[sid]
	if s != nil {
		s.openDone = make(chan error, 1)
	}
	m.mu.Unlock()
	if s == nil {
		s = &Stream{m: m, id: sid, inCh: make(chan []byte, streamQueueDepth), openDone: make(chan error, 1)}
		if err := m.putStream(s); err != nil {
			return err
		}
	}

	if err := m.send(sid, smResume, ticket.Encode()); err != nil {
		return err
	}
	select {
	case err := <-s.openDone:
		return err
	case <-time.After(openTimout):
		return fmt.Errorf("таймаут возобновления потока")
	}
}

// OpenRaw открывает поток с готовой кодировкой цели (TCP или UDP-маркер).
func (m *Mux) OpenRaw(enc []byte) (*Stream, error) {
	if !m.Alive() {
		return nil, m.Err()
	}
	m.mu.Lock()
	sid := m.nextID
	m.nextID++
	m.mu.Unlock()
	s := &Stream{m: m, id: sid, inCh: make(chan []byte, streamQueueDepth), openDone: make(chan error, 1)}
	if err := m.putStream(s); err != nil {
		return nil, err
	}

	if err := m.send(sid, smOpen, enc); err != nil {
		m.remove(sid)
		return nil, err
	}
	select {
	case err := <-s.openDone:
		if err != nil {
			m.remove(sid)
			return nil, err
		}
		return s, nil
	case <-time.After(openTimout):
		m.remove(sid)
		return nil, fmt.Errorf("таймаут открытия потока")
	}
}

func (m *Mux) openRawAuth(payload []byte) (*Stream, error) {
	if !m.Alive() {
		return nil, m.Err()
	}
	m.mu.Lock()
	sid := m.nextID
	m.nextID++
	m.mu.Unlock()
	s := &Stream{m: m, id: sid, inCh: make(chan []byte, streamQueueDepth), openDone: make(chan error, 1)}
	if err := m.putStream(s); err != nil {
		return nil, err
	}

	if err := m.send(sid, smOpenAuth, payload); err != nil {
		m.remove(sid)
		return nil, err
	}
	select {
	case err := <-s.openDone:
		if err != nil {
			m.remove(sid)
			return nil, err
		}
		return s, nil
	case <-time.After(openTimout):
		m.remove(sid)
		return nil, fmt.Errorf("таймаут открытия потока")
	}
}

// ServeMuxWithHandler — расширенная серверная сторона с кастомным CITP-обработчиком.
func ServeMuxWithHandler(conn *Conn, dialTimeout time.Duration, onCITP func(m *Mux, obj *CITPObject)) {
	ServeMuxWithPolicy(conn, dialTimeout, NewPolicyEngine(DefaultPolicy()), onCITP)
}

// ServeMuxWithPolicy enforces one policy for legacy TCP, UDP and DNS-bound OPEN.
func ServeMuxWithPolicy(conn *Conn, dialTimeout time.Duration, policy *PolicyEngine, onCITP func(m *Mux, obj *CITPObject)) {
	serveMuxWithConfig(conn, dialTimeout, policy, onCITP, nil, nil, false)
}

// ServeMuxWithEgress — серверная сторона с каскадом нода→нода: egress-потоки
// (TCP и UDP) идут через заданные дозвонщики (например UpstreamChain.Dial /
// DialUDP), а локальный RESOLVE отключён — домены прозрачно уходят в цепочку
// и резолвятся выходной нодой. Клиент при этом автоматически откатывается на
// legacy open с доменом (см. Mux.Open).
func ServeMuxWithEgress(conn *Conn, dialTimeout time.Duration, policy *PolicyEngine, onCITP func(m *Mux, obj *CITPObject), egress, egressUDP func(hostport string) (net.Conn, error)) {
	serveMuxWithConfig(conn, dialTimeout, policy, onCITP, egress, egressUDP, true)
}

func serveMuxWithConfig(conn *Conn, dialTimeout time.Duration, policy *PolicyEngine, onCITP func(m *Mux, obj *CITPObject), egress, egressUDP func(hostport string) (net.Conn, error), resolveDisabled bool) {
	m := newMux(conn)
	m.onCITP = onCITP
	m.policy = policy
	m.egress = egress
	m.egressUDP = egressUDP
	m.resolveDisabled = resolveDisabled
	if policy != nil {
		m.maxStreams = policy.MaxStreams()
		m.streamLifetime = policy.MaxStreamLifetime()
	}

	// Обработка обычного OPEN (legacy, без ResolutionObject)
	m.onOpen = func(m *Mux, sid uint32, target []byte) {
		if len(target) == 0 || len(target) > maxOpenPayloadBytes {
			_ = m.send(sid, smOpenErr, []byte("open: invalid target length"))
			return
		}
		if target[0] == udpTargetMarker {
			hostport := string(target[1:])
			if err := m.authorizeOpen(hostport); err != nil {
				_ = m.send(sid, smOpenErr, boundedText(err))
				return
			}
			m.serveUDP(sid, hostport)
			return
		}
		hostport, err := ParseTarget(target)
		if err == nil {
			err = m.authorizeOpen(hostport)
		}
		if err != nil {
			_ = m.send(sid, smOpenErr, boundedText(err))
			return
		}
		m.openAndRelay(sid, hostport, dialTimeout)
	}

	// Обработка RESOLVE: нода резолвит домен и возвращает ResolutionObject
	m.onResolve = func(m *Mux, sid uint32, domain string) {
		if m.resolveDisabled {
			// Каскад: домены резолвит выходная нода. Ошибка здесь откатывает
			// клиента на legacy open с доменом (см. Mux.Open), который прозрачно
			// уйдёт в цепочку.
			_ = m.send(sid, smResolveErr, []byte(errResolveViaUpstream.Error()))
			return
		}
		if m.policy != nil {
			if decision, reason := m.policy.EvaluateResolve(domain); decision != PolicyAllow {
				_ = m.send(sid, smResolveErr, boundedText(fmt.Errorf("policy %s: %s", decision, reason)))
				return
			}
		}
		ro, err := ResolveDomain(domain, m.conn.seed)
		if err != nil {
			m.send(sid, smResolveErr, []byte(err.Error()))
			return
		}
		if err := m.issuedResolutions.remember(ro, time.Now()); err != nil {
			_ = m.send(sid, smResolveErr, boundedText(err))
			return
		}
		// Отправляем ResolutionObject как data-кадр, затем сигнализируем OK
		if err := m.send(sid, smResolveOK, ro.Encode()); err != nil {
			return
		}
	}

	// Обработка OPEN с DNS-binding: [u16 roLen][ResolutionObject][ATYP-цель].
	// Нода подключается ТОЛЬКО к адресу из собственного подписанного ответа:
	// Verify (подпись+expiry) → MatchHost (цель ∈ выданному набору) → relay.
	m.onOpenAuth = func(m *Mux, sid uint32, payload []byte) {
		if len(payload) < 2 || len(payload) > maxOpenPayloadBytes {
			m.send(sid, smOpenErr, []byte("open-auth: короткий кадр"))
			return
		}
		roLen := int(binary.BigEndian.Uint16(payload[:2]))
		if len(payload) < 2+roLen {
			m.send(sid, smOpenErr, []byte("open-auth: битый кадр"))
			return
		}
		ro, err := DecodeResolutionObject(payload[2 : 2+roLen])
		if err != nil {
			m.send(sid, smOpenErr, []byte("open-auth: "+err.Error()))
			return
		}
		if err := ro.Verify(m.conn.seed); err != nil {
			m.send(sid, smOpenErr, []byte("open-auth: "+err.Error()))
			return
		}
		if err := m.issuedResolutions.verify(ro, time.Now()); err != nil {
			_ = m.send(sid, smOpenErr, boundedText(err))
			return
		}
		hostport, err := ParseTarget(payload[2+roLen:])
		if err != nil {
			m.send(sid, smOpenErr, []byte("open-auth: "+err.Error()))
			return
		}
		host, _, err := net.SplitHostPort(hostport)
		if err != nil {
			m.send(sid, smOpenErr, []byte("open-auth: "+err.Error()))
			return
		}
		if !ro.MatchHost(host) {
			// Цель не из подписанного набора — подмена/rebinding, отказ.
			m.send(sid, smOpenErr, []byte("open-auth: адрес не из подписанного resolution"))
			return
		}
		if err := m.authorizeOpen(hostport); err != nil {
			_ = m.send(sid, smOpenErr, boundedText(err))
			return
		}
		m.openAndRelay(sid, hostport, dialTimeout)
	}

	// Обработка RESUME: возобновление стрима по тикету миграции
	m.onResume = func(m *Mux, sid uint32, payload []byte) {
		ticket, err := DecodeMigrationTicket(payload)
		if err != nil {
			m.send(sid, smResumeErr, []byte("resume: invalid ticket"))
			return
		}
		if err := ticket.Verify(m.conn.seed, time.Now().UnixMilli()); err != nil {
			m.send(sid, smResumeErr, []byte("resume: "+err.Error()))
			return
		}
		// Проверяем наличие активного сохраненного потока
		m.mu.Lock()
		s := m.streams[ticket.StreamID]
		m.mu.Unlock()
		if s == nil {
			m.send(sid, smResumeErr, []byte("resume: stream not found or expired"))
			return
		}
		m.send(sid, smResumeOK, nil)
	}

	m.loop()
}

// ServeMux — стандартная серверная сторона: принимает потоки, подключается к целям.
func ServeMux(conn *Conn, dialTimeout time.Duration) {
	ServeMuxWithHandler(conn, dialTimeout, nil)
}

// openAndRelay устанавливает TCP-соединение к цели и начинает релей.
func (m *Mux) openAndRelay(sid uint32, hostport string, dialTimeout time.Duration) {
	var rc net.Conn
	var err error
	if m.egress != nil {
		// Каскад: поток до цели через вышестоящую ноду (она же резолвит домены).
		rc, err = m.egress(hostport)
	} else {
		rc, err = net.DialTimeout("tcp", hostport, dialTimeout)
	}
	if err != nil {
		m.send(sid, smOpenErr, []byte(err.Error()))
		return
	}
	if tc, ok := rc.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	s := &Stream{m: m, id: sid, inCh: make(chan []byte, streamQueueDepth)}
	if err := m.putStream(s); err != nil {
		_ = rc.Close()
		_ = m.send(sid, smOpenErr, boundedText(err))
		return
	}
	if err := m.send(sid, smOpenOK, nil); err != nil {
		rc.Close()
		m.remove(sid)
		return
	}
	// цель → поток
	go func() {
		buf := make([]byte, muxMaxData)
		for {
			n, err := rc.Read(buf)
			if n > 0 {
				if _, werr := s.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		s.Close()
	}()
	// поток → цель
	go func() {
		defer rc.Close()
		buf := make([]byte, 32*1024)
		for {
			n, err := s.Read(buf)
			if n > 0 {
				if _, werr := rc.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
}

// serveUDP — серверная сторона UDP-релея: датаграммы клиента (с 2-байтным
// префиксом длины) отправляются на цель по UDP, ответы возвращаются тем же
// обрамлением. Простаивший релей закрывается через 120 секунд.
// serveUDPChain — UDP-associate поверх каскада: кадры [u16 len][packet] из
// клиентского потока прозрачно копируются в UDP-поток вышестоящей ноды (та же
// кадрировка на том конце), реальный UDP уходит с IP выходной ноды.
func (m *Mux) serveUDPChain(sid uint32, hostport string) {
	uc, err := m.egressUDP(hostport)
	if err != nil {
		m.send(sid, smOpenErr, []byte(err.Error()))
		return
	}
	s := &Stream{m: m, id: sid, inCh: make(chan []byte, streamQueueDepth)}
	if err := m.putStream(s); err != nil {
		_ = uc.Close()
		_ = m.send(sid, smOpenErr, boundedText(err))
		return
	}
	if err := m.send(sid, smOpenOK, nil); err != nil {
		uc.Close()
		m.remove(sid)
		return
	}
	go func() { defer uc.Close(); defer s.Close(); _, _ = io.Copy(uc, s) }()
	go func() { defer uc.Close(); defer s.Close(); _, _ = io.Copy(s, uc) }()
}

func (m *Mux) serveUDP(sid uint32, hostport string) {
	if m.egressUDP != nil {
		m.serveUDPChain(sid, hostport)
		return
	}
	uc, err := net.Dial("udp", hostport)
	if err != nil {
		m.send(sid, smOpenErr, []byte(err.Error()))
		return
	}
	s := &Stream{m: m, id: sid, inCh: make(chan []byte, streamQueueDepth)}
	if err := m.putStream(s); err != nil {
		_ = uc.Close()
		_ = m.send(sid, smOpenErr, boundedText(err))
		return
	}
	if err := m.send(sid, smOpenOK, nil); err != nil {
		uc.Close()
		m.remove(sid)
		return
	}

	// поток → udp
	go func() {
		defer uc.Close()
		defer s.Close()
		lb := make([]byte, 2)
		for {
			if _, err := io.ReadFull(s, lb); err != nil {
				return
			}
			n := int(binary.BigEndian.Uint16(lb))
			if n == 0 {
				return
			}
			d := make([]byte, n)
			if _, err := io.ReadFull(s, d); err != nil {
				return
			}
			if _, err := uc.Write(d); err != nil {
				return
			}
		}
	}()
	// udp → поток
	go func() {
		defer s.Close()
		defer uc.Close()
		buf := make([]byte, 2+65535)
		for {
			uc.SetReadDeadline(time.Now().Add(120 * time.Second))
			n, err := uc.Read(buf[2:])
			if err != nil {
				return
			}
			binary.BigEndian.PutUint16(buf[:2], uint16(n))
			if _, err := s.Write(buf[:2+n]); err != nil {
				return
			}
		}
	}()
}
