// Package mobilecore — ядро Chameleon VPN для Android (gomobile bind).
//
// Kotlin-сторона (VpnService) создаёт tun-интерфейс и передаёт сюда его
// fd + реализацию Protector (VpnService.protect — защита сокета к ноде
// от петли через VPN). Ядро поднимает локальный SOCKS5 (TCP CONNECT +
// UDP ASSOCIATE → датаграммы через туннель, так работает и DNS) и
// подключает tun2socks-движок на этом fd.
package mobilecore

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"chameleon/internal/chameleon"

	_ "golang.org/x/mobile/bind" // требуется gomobile bind
)

// Protector реализуется на стороне Kotlin: VpnService.protect(fd).
type Protector interface {
	Protect(fd int32) bool
}

// TrafficSample — компактная выборка трафика для анализа PackMorph.
// Сжимается и периодически сбрасывается в UI для анализа ИИ-агентом.
type TrafficSample struct {
	TimestampMs int64  `json:"ts"`     // время выборки
	Dir         string `json:"dir"`    // "up" или "down"
	Size        int    `json:"size"`   // размер пакета
	IntervalMs  int    `json:"ivl"`    // интервал с предыдущим пакетом
	Proto       string `json:"proto"`  // "tcp", "udp", "dns"
	Target      string `json:"target"` // host:port назначения
	IsPadding   bool   `json:"pad"`    // является ли паддингом
}

// TrafficProfile — агрегированная статистика трафика за окно.
type TrafficProfile struct {
	WindowMs      int64          `json:"window_ms"`
	Samples       int            `json:"samples"`
	AvgSize       float64        `json:"avg_size"`
	SizeStdDev    float64        `json:"size_stddev"`
	AvgInterval   float64        `json:"avg_interval_ms"`
	IatStdDev     float64        `json:"iat_stddev_ms"`
	ByteRate      float64        `json:"byte_rate"`
	PacketRate    float64        `json:"packet_rate"`
	SizeHistogram map[int]int    `json:"size_hist"`
	ProtoMix      map[string]int `json:"proto_mix"`
}

// BypassRule — правило обхода VPN для конкретного трафика.
type BypassRule struct {
	Type  string `json:"type"`  // "app", "domain", "ip"
	Value string `json:"value"` // package name, domain pattern, или IP/CIDR
}

// NewBypassRule создает новое правило обхода.
func NewBypassRule(typ, value string) BypassRule {
	return BypassRule{
		Type:  typ,
		Value: value,
	}
}

var (
	mu         sync.Mutex
	dialMu     sync.Mutex
	running    bool
	socksLn    net.Listener
	mx         *chameleon.Mux
	nodeAddr   string
	nodePub    string
	nodeClient string
	protector  Protector
	logMu      sync.Mutex
	lastLog    []string
	activeWg   sync.WaitGroup

	ctx    context.Context
	cancel context.CancelFunc

	upBytes   atomic.Int64 // трафик через туннель (для индикации в UI)
	downBytes atomic.Int64

	// Сбор сетевых логов для анализа PackMorph
	trafficMu      sync.Mutex
	trafficSamples []TrafficSample
	trafficLog     []TrafficSample
	lastUpTime     int64
	lastDownTime   int64
	profileMu      sync.Mutex
	currentProfile *TrafficProfile
	bypassRules    []BypassRule
	gameBypass     bool
	russianBypass  bool
)

var logPath string

// SetLogPath направляет журнал в файл (полный лог на устройстве).
func SetLogPath(path string) {
	logMu.Lock()
	logPath = path
	logMu.Unlock()
}

func logf(format string, args ...any) {
	line := time.Now().Format("15:04:05.000") + "  " + fmt.Sprintf(format, args...)
	logMu.Lock()
	lastLog = append(lastLog, line)
	if len(lastLog) > 4000 {
		lastLog = lastLog[len(lastLog)-4000:]
	}
	path := logPath
	logMu.Unlock()
	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err == nil {
			_, _ = f.WriteString(time.Now().Format("2006-01-02 ") + line + "\n")
			_ = f.Close()
		}
	}
}

// Logs — последние строки журнала (для отображения в UI).
func Logs() string {
	logMu.Lock()
	defer logMu.Unlock()
	out := ""
	for _, l := range lastLog {
		out += l + "\n"
	}
	return out
}

// CompressedLogs возвращает сжатый журнал трафика для анализа ИИ-агентом.
// Используется gzip для уменьшения размера перед передачей в UI.
func CompressedLogs() string {
	trafficMu.Lock()
	samples := make([]TrafficSample, len(trafficLog))
	copy(samples, trafficLog)
	trafficMu.Unlock()

	if len(samples) == 0 {
		return ""
	}

	data, err := json.Marshal(samples)
	if err != nil {
		return ""
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(data); err != nil {
		return ""
	}
	gz.Close()

	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// TrafficProfileJSON возвращает агрегированный профиль трафика в JSON.
func TrafficProfileJSON() string {
	profileMu.Lock()
	defer profileMu.Unlock()
	if currentProfile == nil {
		return ""
	}
	data, err := json.Marshal(currentProfile)
	if err != nil {
		return ""
	}
	return string(data)
}

// AddTrafficSample добавляет выборку трафика для анализа.
func AddTrafficSample(dir string, size int, proto string, target string, isPadding bool) {
	now := time.Now().UnixMilli()
	var intervalMs int
	var lastTime *int64

	trafficMu.Lock()
	defer trafficMu.Unlock()

	switch dir {
	case "up":
		lastTime = &lastUpTime
	case "down":
		lastTime = &lastDownTime
	}

	if lastTime != nil && *lastTime > 0 {
		intervalMs = int(now - *lastTime)
	}
	if lastTime != nil {
		*lastTime = now
	}

	sample := TrafficSample{
		TimestampMs: now,
		Dir:         dir,
		Size:        size,
		IntervalMs:  intervalMs,
		Proto:       proto,
		Target:      target,
		IsPadding:   isPadding,
	}

	trafficLog = append(trafficLog, sample)
	trafficSamples = append(trafficSamples, sample)

	// Ограничиваем размер лога
	if len(trafficLog) > 5000 {
		trafficLog = trafficLog[len(trafficLog)-5000:]
	}
	if len(trafficSamples) > 1000 {
		trafficSamples = trafficSamples[len(trafficSamples)-1000:]
	}

	// Периодически обновляем профиль
	if len(trafficSamples) >= 100 {
		updateProfileLocked()
	}
}

// updateProfileLocked обновляет агрегированный профиль трафика.
func updateProfileLocked() {
	if len(trafficSamples) == 0 {
		return
	}

	var totalSize float64
	var totalInterval float64
	var sizeSqSum float64
	var intervalSqSum float64
	var intervalCount float64
	sizeHist := make(map[int]int)
	protoMix := make(map[string]int)

	for _, s := range trafficSamples {
		size := float64(s.Size)
		totalSize += size
		if s.IntervalMs > 0 {
			interval := float64(s.IntervalMs)
			totalInterval += interval
			intervalSqSum += interval * interval
			intervalCount++
		}
		sizeSqSum += size * size
		sizeHist[s.Size/100*100]++
		protoMix[s.Proto]++
	}

	n := float64(len(trafficSamples))
	avgSize := totalSize / n
	avgInterval := 0.0
	if intervalCount > 0 {
		avgInterval = totalInterval / intervalCount
	}

	var sizeStdDev, iatStdDev float64
	if n > 1 {
		sizeStdDev = sqrt((sizeSqSum/n - avgSize*avgSize) * n / (n - 1))
	}
	if intervalCount > 1 {
		iatStdDev = sqrt((intervalSqSum/intervalCount - avgInterval*avgInterval) * intervalCount / (intervalCount - 1))
	}

	windowMs := int64(0)
	if len(trafficSamples) > 1 {
		windowMs = trafficSamples[len(trafficSamples)-1].TimestampMs - trafficSamples[0].TimestampMs
	}

	byteRate := 0.0
	packetRate := 0.0
	if windowMs > 0 {
		windowSeconds := float64(windowMs) / 1000.0
		byteRate = totalSize / windowSeconds
		packetRate = n / windowSeconds
	}

	profile := &TrafficProfile{
		WindowMs:      windowMs,
		Samples:       len(trafficSamples),
		AvgSize:       avgSize,
		SizeStdDev:    sizeStdDev,
		AvgInterval:   avgInterval,
		IatStdDev:     iatStdDev,
		ByteRate:      byteRate,
		PacketRate:    packetRate,
		SizeHistogram: sizeHist,
		ProtoMix:      protoMix,
	}
	profileMu.Lock()
	currentProfile = profile
	profileMu.Unlock()

	// Сбрасываем выборки для следующего окна
	trafficSamples = trafficSamples[:0]
}

func sqrt(x float64) float64 {
	if x <= 0 {
		return 0
	}
	z := x
	if z < 1 {
		z = 1
	}
	for i := 0; i < 10; i++ {
		z = z - (z*z-x)/(2*z)
	}
	return z
}

// ShouldBypassDomain проверяет, должен ли трафик к домену обходить VPN.
func ShouldBypassDomain(domain string) bool {
	mu.Lock()
	defer mu.Unlock()
	if !russianBypass {
		return false
	}
	for _, rule := range bypassRules {
		if rule.Type == "domain" {
			if domainMatches(domain, rule.Value) {
				return true
			}
		}
	}
	return false
}

// ShouldBypassApp проверяет, должен ли трафик от приложения обходить VPN.
func ShouldBypassApp(packageName string) bool {
	mu.Lock()
	defer mu.Unlock()
	if !gameBypass {
		return false
	}
	for _, rule := range bypassRules {
		if rule.Type == "app" && rule.Value == packageName {
			return true
		}
	}
	return false
}

// domainMatches проверяет, соответствует ли домен паттерну.
func domainMatches(domain, pattern string) bool {
	if pattern == "*" {
		return true
	}
	if len(pattern) > 0 && pattern[0] == '*' {
		suffix := pattern[1:]
		return strings.HasSuffix(domain, suffix)
	}
	return domain == pattern || strings.HasSuffix(domain, "."+pattern)
}

// SetBypassRules устанавливает правила обхода VPN.
func SetBypassRules(rules []BypassRule, enableGameBypass, enableRussianBypass bool) {
	mu.Lock()
	defer mu.Unlock()
	bypassRules = append([]BypassRule(nil), rules...)
	gameBypass = enableGameBypass
	russianBypass = enableRussianBypass
	logf("Bypass rules updated: %d rules, game=%v, russian=%v", len(rules), gameBypass, russianBypass)
}

// GetBypassRules возвращает текущие правила обхода.
func GetBypassRules() string {
	mu.Lock()
	defer mu.Unlock()
	data, err := json.Marshal(bypassRules)
	if err != nil {
		return "[]"
	}
	return string(data)
}

// Start поднимает VPN: tunFd — fd интерфейса из VpnService.Builder.establish(),
// addr/pubkey — нода, clientPriv — персональный ключ устройства (белый
// список на ноде), p — Protector. Возвращает пустую строку или ошибку.
// Любая паника превращается в строку ошибки — приложение не падает.
func Start(addr, pubkey, clientPriv string, tunFd int32, p Protector) (errStr string) {
	var fail func(error) string
	defer func() {
		if r := recover(); r != nil {
			err := fmt.Errorf("внутренний сбой: %v", r)
			if fail != nil {
				errStr = fail(err)
			} else {
				errStr = err.Error()
				logf("ПАНИКА: %v", r)
			}
		}
	}()

	mu.Lock()
	if running || ksRun {
		mu.Unlock()
		return "уже запущено"
	}
	running = true
	modeName.Store("citp")
	ctx, cancel = context.WithCancel(context.Background())
	nodeAddr, nodePub, nodeClient, protector = addr, pubkey, clientPriv, p
	upBytes.Store(0)
	downBytes.Store(0)
	mu.Unlock()

	fail = func(e error) string {
		stopVPNStack()
		mu.Lock()
		running = false
		if cancel != nil {
			cancel()
			cancel = nil
		}
		if socksLn != nil {
			socksLn.Close()
			socksLn = nil
		}
		if mx != nil {
			mx.Conn().Close()
			mx = nil
		}
		mu.Unlock()
		logf("ошибка запуска: %v", e)
		return e.Error()
	}

	if err := startSocks(); err != nil {
		return fail(fmt.Errorf("локальный SOCKS: %w", err))
	}

	// Проверяем ноду ДО поднятия стека: если рукопожатие не пройдёт,
	// пользователь сразу увидит причину, а не «подключено, но ничего не грузит».
	logf("рукопожатие с нодой %s...", addr)
	t0 := time.Now()
	// Serialize the initial dial with reconnects started by early SOCKS traffic.
	dialMu.Lock()
	conn, err := chameleon.DialNodeHook(nodeAddr, nodePub, nodeClient, 10*time.Second, protectControl)
	if err != nil {
		dialMu.Unlock()
		return fail(fmt.Errorf("нода не отвечает: %w", err))
	}
	mu.Lock()
	if !running {
		mu.Unlock()
		_ = conn.Close()
		dialMu.Unlock()
		return fail(fmt.Errorf("запуск отменён"))
	}
	mx = chameleon.NewMuxClient(conn)
	mu.Unlock()
	dialMu.Unlock()
	logf("сеанс установлен, пинг %d мс", time.Since(t0).Milliseconds())

	if err := startVPNStack(tunFd); err != nil {
		return fail(err)
	}
	mu.Lock()
	cancelled := !running
	mu.Unlock()
	if cancelled {
		return fail(fmt.Errorf("запуск отменён"))
	}
	logf("стек поднят, трафик идёт через ноду")
	return ""
}

// Stop останавливает стек, SOCKS и сеанс к ноде.
func Stop() {
	stopKS()
	mu.Lock()
	if !running {
		mu.Unlock()
		return
	}
	running = false
	modeName.Store("")
	if cancel != nil {
		cancel()
		cancel = nil
	}
	stopVPNStack()
	if socksLn != nil {
		socksLn.Close()
		socksLn = nil
	}
	if mx != nil {
		mx.Conn().Close()
		mx = nil
	}
	mu.Unlock()

	// Неблокирующее / ограниченное по времени ожидание активных горутин
	done := make(chan struct{})
	go func() {
		activeWg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
	}

	logf("ядро остановлено")
}

// IsRunning — состояние для UI.
func IsRunning() bool {
	mu.Lock()
	defer mu.Unlock()
	return running
}

func protectControl(fd uintptr) {
	mu.Lock()
	p := protector
	mu.Unlock()
	if p == nil {
		logf("ВНИМАНИЕ: нет Protector — сокет к ноде попадёт в петлю VPN!")
		return
	}
	if !p.Protect(int32(fd)) {
		// Без protect() сокет к ноде уходит обратно в туннель → петля,
		// внешне это выглядит как «подключено, но ничего не работает».
		logf("ВНИМАНИЕ: VpnService.protect(%d) вернул false — возможна петля трафика", fd)
	}
}

// Счётчики и пинг для индикации в UI (Kotlin опрашивает раз в секунду).
func UpBytes() int64   { return upBytes.Load() }
func DownBytes() int64 { return downBytes.Load() }

// RttMs — последний измеренный RTT до ноды в миллисекундах (-1, если неизвестен).
func RttMs() int64 {
	mu.Lock()
	m := mx
	mu.Unlock()
	if m == nil || !m.Alive() {
		return -1
	}
	return m.RTT().Milliseconds()
}

// ensureMux returns a live session without holding mu while dialing. The
// separate dialMu prevents concurrent SOCKS streams from creating duplicate
// replacement sessions.
func ensureMux() (*chameleon.Mux, error) {
	dialMu.Lock()
	defer dialMu.Unlock()

	mu.Lock()
	if !running {
		mu.Unlock()
		return nil, fmt.Errorf("VPN остановлен")
	}
	current := mx
	if current != nil && current.Alive() {
		mu.Unlock()
		return current, nil
	}
	if current != nil {
		mx = nil
	}
	addr, pub, client := nodeAddr, nodePub, nodeClient
	mu.Unlock()

	if current != nil {
		_ = current.Conn().Close()
	}
	conn, err := chameleon.DialNodeHook(addr, pub, client, 10*time.Second, protectControl)
	if err != nil {
		return nil, err
	}
	replacement := chameleon.NewMuxClient(conn)

	mu.Lock()
	if !running {
		mu.Unlock()
		_ = conn.Close()
		return nil, fmt.Errorf("VPN остановлен")
	}
	// Stop/Start or another lifecycle transition may have installed a live
	// session while the network dial was in progress.
	if mx != nil && mx.Alive() {
		existing := mx
		mu.Unlock()
		_ = conn.Close()
		return existing, nil
	}
	mx = replacement
	mu.Unlock()
	logf("сеанс к ноде установлен")
	return replacement, nil
}

// openStream открывает TCP-поток к цели через живой сеанс.
func openStream(target string) (*chameleon.Stream, error) {
	m, err := ensureMux()
	if err != nil {
		return nil, err
	}
	return m.Open(target)
}

func startSocks() error {
	ln, err := net.Listen("tcp", "127.0.0.1:11080")
	if err != nil {
		return err
	}
	mu.Lock()
	socksLn = ln
	mu.Unlock()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			activeWg.Add(1)
			go func(conn net.Conn) {
				defer activeWg.Done()
				handleSocks(conn)
			}(c)
		}
	}()
	return nil
}

func handleSocks(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))

	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil || head[0] != 0x05 {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	noAuth := false
	for _, method := range methods {
		if method == 0x00 {
			noAuth = true
			break
		}
	}
	if !noAuth {
		_, _ = c.Write([]byte{0x05, 0xff})
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil || req[0] != 0x05 {
		return
	}
	host, err := readSocksAddr(c, req[3])
	if err != nil {
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(pb))))

	switch req[1] {
	case 0x01: // CONNECT
		serveTCP(c, target)
	case 0x03: // UDP ASSOCIATE
		serveUDPAssociate(c)
	default:
		writeSocksReply(c, 0x07)
	}
}

func serveTCP(c net.Conn, target string) {
	bypass := shouldBypassTarget(target)
	var remote io.ReadWriteCloser
	var err error
	if bypass {
		remote, err = dialProtected("tcp", target)
		if err == nil {
			logf("обход VPN: TCP %s", target)
		}
	} else {
		remote, err = openStream(target)
	}
	if err != nil {
		writeSocksReply(c, 0x05)
		return
	}
	defer remote.Close()
	c.SetDeadline(time.Time{})
	if err := writeSocksReply(c, 0x00); err != nil {
		return
	}

	mu.Lock()
	localCtx := ctx
	mu.Unlock()
	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(remote, c)
		upBytes.Add(n)
		AddTrafficSample("up", int(n), "tcp", target, bypass)
		_ = remote.Close()
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(c, remote)
		downBytes.Add(n)
		AddTrafficSample("down", int(n), "tcp", target, bypass)
		done <- struct{}{}
	}()
	if localCtx != nil {
		select {
		case <-done:
			<-done
		case <-localCtx.Done():
			_ = c.Close()
			_ = remote.Close()
			<-done
			<-done
		}
	} else {
		<-done
		<-done
	}
}

// serveUDPAssociate: датаграммы клиента (DNS и пр.) заворачиваются в
// UDP-релей через туннель. На каждую цель — свой поток мультиплексора.
func serveUDPAssociate(c net.Conn) {
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		writeSocksReply(c, 0x05)
		return
	}
	defer udp.Close()
	port := udp.LocalAddr().(*net.UDPAddr).Port
	reply := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, byte(port >> 8), byte(port)}
	if _, err := c.Write(reply); err != nil {
		return
	}
	c.SetDeadline(time.Time{})
	quit := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, c); close(quit) }()

	type relay struct {
		st     *chameleon.Stream
		direct net.Conn
		target string
		bypass bool
	}
	relays := map[string]*relay{}
	defer func() {
		for _, r := range relays {
			if r.st != nil {
				_ = r.st.Close()
			}
			if r.direct != nil {
				_ = r.direct.Close()
			}
		}
	}()
	var clientAddrMu sync.RWMutex
	var clientAddr *net.UDPAddr
	buf := make([]byte, 65535)

	writeBack := func(target string, payload []byte, bypass bool) {
		clientAddrMu.RLock()
		dst := clientAddr
		clientAddrMu.RUnlock()
		if dst == nil {
			return
		}
		hdr := socksUDPHeader(target)
		out := append(append([]byte(nil), hdr...), payload...)
		_, _ = udp.WriteTo(out, dst)
		downBytes.Add(int64(len(payload)))
		AddTrafficSample("down", len(payload), "udp", target, bypass)
	}

	for {
		select {
		case <-quit:
			return
		default:
		}
		udp.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, src, err := udp.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		clientAddrMu.Lock()
		clientAddr = src.(*net.UDPAddr)
		clientAddrMu.Unlock()
		d := buf[:n]
		if len(d) < 10 || d[0] != 0 || d[1] != 0 || d[2] != 0 {
			continue
		}
		host, off, _, ok := parseUDPDatagramTarget(d)
		if !ok {
			continue
		}
		target := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(d[off-2:off]))))
		payload := append([]byte(nil), d[off:]...)
		wantBypass := shouldBypassUDP(target, payload)
		key := target
		if wantBypass {
			key = "direct|" + target
		} else {
			key = "vpn|" + target
		}
		r := relays[key]
		if r == nil {
			r = &relay{target: target, bypass: wantBypass}
			if wantBypass {
				r.direct, err = dialProtected("udp", target)
				if err != nil {
					continue
				}
				logf("обход VPN: UDP %s", target)
				go func(r *relay) {
					rb := make([]byte, 65535)
					for {
						dn, e := r.direct.Read(rb)
						if e != nil {
							return
						}
						writeBack(r.target, rb[:dn], true)
					}
				}(r)
			} else {
				r.st, err = openUDPStream(target)
				if err != nil {
					continue
				}
				go func(r *relay) {
					rb := make([]byte, 2+65535)
					for {
						if _, e := io.ReadFull(r.st, rb[:2]); e != nil {
							return
						}
						dn := int(binary.BigEndian.Uint16(rb[:2]))
						if dn > 65535 {
							return
						}
						if _, e := io.ReadFull(r.st, rb[:dn]); e != nil {
							return
						}
						writeBack(r.target, rb[:dn], false)
					}
				}(r)
			}
			relays[key] = r
		}
		if r.bypass {
			_, err = r.direct.Write(payload)
		} else {
			frame := make([]byte, 2+len(payload))
			binary.BigEndian.PutUint16(frame[:2], uint16(len(payload)))
			copy(frame[2:], payload)
			_, err = r.st.Write(frame)
		}
		if err != nil {
			if r.st != nil {
				_ = r.st.Close()
			}
			if r.direct != nil {
				_ = r.direct.Close()
			}
			delete(relays, key)
			continue
		}
		upBytes.Add(int64(len(payload)))
		AddTrafficSample("up", len(payload), "udp", target, r.bypass)
	}
}

// parseUDPDatagramTarget validates a SOCKS5 UDP header and returns the
// destination host, payload offset, and address type.
func parseUDPDatagramTarget(d []byte) (host string, off int, atyp byte, ok bool) {
	if len(d) < 4 {
		return "", 0, 0, false
	}
	atyp = d[3]
	switch atyp {
	case 0x01:
		if len(d) < 10 {
			return "", 0, 0, false
		}
		return net.IP(d[4:8]).String(), 10, atyp, true
	case 0x03:
		if len(d) < 5 {
			return "", 0, 0, false
		}
		l := int(d[4])
		if len(d) < 5+l+2 {
			return "", 0, 0, false
		}
		return string(d[5 : 5+l]), 5 + l + 2, atyp, true
	case 0x04:
		if len(d) < 22 {
			return "", 0, 0, false
		}
		return net.IP(d[4:20]).String(), 22, atyp, true
	default:
		return "", 0, 0, false
	}
}

func openUDPStream(target string) (*chameleon.Stream, error) {
	m, err := ensureMux()
	if err != nil {
		return nil, err
	}
	return m.OpenUDP(target)
}

func readSocksAddr(c net.Conn, atyp byte) (string, error) {
	switch atyp {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	case 0x03:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(c, lb); err != nil {
			return "", err
		}
		b := make([]byte, int(lb[0]))
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		return string(b), nil
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	}
	return "", fmt.Errorf("atyp %d не поддерживается", atyp)
}

func writeSocksReply(c net.Conn, rep byte) error {
	_, err := c.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

// GenClientKey генерирует приватный ключ устройства (хранить локально,
// передавать в Start). gomobile не умеет два строковых результата,
// поэтому публичная часть выводится отдельно через PubFromPriv.
func GenClientKey() string {
	priv, _, err := chameleon.GenerateNodeKey()
	if err != nil {
		return ""
	}
	return priv
}

// PubFromPriv выводит публичный ключ из приватного (для белого списка ноды).
func PubFromPriv(privB64 string) string {
	priv, err := chameleon.ParseNodePrivKey(privB64)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())
}

// socksUDPHeader строит SOCKS5-UDP заголовок с реальным адресом источника.
func socksUDPHeader(target string) []byte {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return []byte{0, 0, 0, 0x01, 0, 0, 0, 0, 0, 0}
	}
	port, _ := strconv.Atoi(portStr)
	h := []byte{0, 0, 0}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			h = append(h, 0x01, ip4[0], ip4[1], ip4[2], ip4[3])
		} else if ip16 := ip.To16(); ip16 != nil {
			h = append(h, 0x04)
			h = append(h, ip16...)
		}
	} else if len(host) < 256 {
		h = append(h, 0x03, byte(len(host)))
		h = append(h, []byte(host)...)
	} else {
		return []byte{0, 0, 0, 0x01, 0, 0, 0, 0, 0, 0}
	}
	return append(h, byte(port>>8), byte(port))
}
