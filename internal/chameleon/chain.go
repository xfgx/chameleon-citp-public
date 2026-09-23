package chameleon

// chain.go — каскад нода→нода: входная (RU) нода заворачивает egress-потоки в
// аутентифицированный сеанс к вышестоящей (зарубежной) ноде вместо прямого
// дозвона к цели.
//
// Зачем: выходной IP входной ноды российский — заблокированные в РФ ресурсы с
// него недоступны. В цепочке клиент → вход → выход цель видит IP выходной
// ноды; провайдер клиента видит внутрироссийское соединение ко входу; выход
// видит только IP входа, не клиента.
//
// Принципы:
//   - fail-closed: аплинк мёртв → ошибка, никакого молчаливого отката на
//     прямой дозвон (иначе трафик «светится» с IP входной ноды);
//   - домены НЕ резолвятся входной нодой: RESOLVE на ней отключён
//     (resolveDisabled в serveMuxWithConfig), домен прозрачно уходит в
//     цепочку и резолвится выходной нодой с её точки зрения;
//   - опциональный direct-список доменных суффиксов для прямого дозвона
//     (RU-локальные сервисы, чтобы не гонять их через зарубежный выход).

import (
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ErrChainDown — аплинк к вышестоящей ноде сейчас недоступен (fail-closed).
var ErrChainDown = errors.New("chain: сеанс к вышестоящей ноде недоступен")

// UpstreamChain — постоянный клиентский сеанс этой ноды к вышестоящей ноде
// с автоматическим переподключением. Потокобезопасен.
type UpstreamChain struct {
	addr   string
	pub    *ecdh.PublicKey
	priv   *ecdh.PrivateKey
	direct []string // доменные суффиксы прямого дозвона (без цепочки)

	mu     sync.RWMutex
	mx     *Mux
	conn   net.Conn
	legacy atomic.Bool // вышестоящая нода старой сборки (без RESOLVE) -> legacy open

	stopCh chan struct{}
	once   sync.Once
	wg     sync.WaitGroup
}

// NewUpstreamChain готовит каскад. clientPriv — клиентский ключ ЭТОЙ ноды для
// рукопожатия с вышестоящей (если у той allowlist, наш ClientPubB64 надо туда
// добавить). directSuffixes — домены для прямого дозвона мимо цепочки.
func NewUpstreamChain(addr, pubB64 string, clientPriv *ecdh.PrivateKey, directSuffixes []string) (*UpstreamChain, error) {
	if strings.TrimSpace(addr) == "" {
		return nil, errors.New("chain: пустой адрес вышестоящей ноды")
	}
	pub, err := ParseNodePubKey(pubB64)
	if err != nil {
		return nil, fmt.Errorf("chain: %w", err)
	}
	if clientPriv == nil {
		return nil, errors.New("chain: nil клиентский ключ")
	}
	return &UpstreamChain{addr: addr, pub: pub, priv: clientPriv, direct: directSuffixes, stopCh: make(chan struct{})}, nil
}

// ClientPubB64 — наш публичный ключ как клиента вышестоящей ноды (для её
// allowlist, если тот включён).
func (u *UpstreamChain) ClientPubB64() string {
	return base64.RawURLEncoding.EncodeToString(u.priv.PublicKey().Bytes())
}

// Start запускает фоновый контур поддержания аплинка.
func (u *UpstreamChain) Start() {
	u.wg.Add(1)
	go u.maintain()
}

func (u *UpstreamChain) maintain() {
	defer u.wg.Done()
	backoff := time.Second
	for {
		select {
		case <-u.stopCh:
			return
		default:
		}
		if mx := u.getMux(); mx == nil || !mx.Alive() {
			u.reset()
			if err := u.connectOnce(); err != nil {
				select {
				case <-u.stopCh:
					return
				case <-time.After(backoff):
				}
				if backoff < 15*time.Second {
					backoff *= 2
				}
				continue
			}
			backoff = time.Second
		}
		select {
		case <-u.stopCh:
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func (u *UpstreamChain) connectOnce() error {
	cc, err := net.DialTimeout("tcp", u.addr, 10*time.Second)
	if err != nil {
		return err
	}
	// Жёсткий дедлайн на рукопожатие: если выход молчит (strike-list/blackhole
	// или фильтрация на пути), падаем за ≤12с вместо многочасового висения на
	// чтении — иначе клиентские открытия копятся и забивают пул обработчиков.
	_ = cc.SetDeadline(time.Now().Add(12 * time.Second))
	sess, err := ClientHandshake(cc, u.pub, u.priv)
	if err != nil {
		_ = cc.Close()
		return err
	}
	_ = cc.SetDeadline(time.Time{})
	conn, err := NewClientConn(cc, sess)
	if err != nil {
		_ = cc.Close()
		return err
	}
	u.mu.Lock()
	u.mx = NewMuxClient(conn)
	u.conn = cc
	u.mu.Unlock()
	u.probeUpstream()
	return nil
}

// probeUpstream определяет сборку вышестоящей ноды: если та понимает RESOLVE
// (новая сборка с DNS-binding), Resolve вернётся быстро (даже с ошибкой
// резолва несуществующего домена — главное, что сервер ответил). Старая
// сборка на smResolve молчит (обработчика не было) — тогда домены открываем
// сразу legacy-кадром, не сжигая openTimout на заведомо мёртвом RESOLVE.
func (u *UpstreamChain) probeUpstream() {
	mx := u.getMux()
	if mx == nil {
		return
	}
	done := make(chan struct{})
	go func() { _, _ = mx.Resolve("chain-probe.invalid"); close(done) }()
	select {
	case <-done:
		u.legacy.Store(false)
	case <-time.After(4 * time.Second):
		u.legacy.Store(true)
	}
}

// Status — состояние аплинка для журнала/оператора: подключены ли и говорит
// ли выходная нода на новом протоколе (RESOLVE).
func (u *UpstreamChain) Status() (connected, legacy bool) {
	mx := u.getMux()
	return mx != nil && mx.Alive(), u.legacy.Load()
}

func (u *UpstreamChain) getMux() *Mux {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.mx
}

// reset сбрасывает мёртвый аплинк (maintain переподключит).
func (u *UpstreamChain) reset() {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.conn != nil {
		_ = u.conn.Close()
	}
	u.mx = nil
	u.conn = nil
}

// matchDirect — домен из direct-списка?
func (u *UpstreamChain) matchDirect(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.Trim(strings.TrimSpace(host), "[]"), "."))
	for _, suf := range u.direct {
		suf = strings.ToLower(strings.TrimSpace(suf))
		if suf == "" {
			continue
		}
		if strings.HasPrefix(suf, ".") {
			if strings.HasSuffix(host, suf) {
				return true
			}
			continue
		}
		if host == suf || strings.HasSuffix(host, "."+suf) {
			return true
		}
	}
	return false
}

// upstreamMux возвращает живой аплинк. Переподключением занимается ТОЛЬКО
// maintain() (один контур, с backoff и дедлайнами) — здесь лишь ждём его
// результат до 20с: конкурентные Dial не штампуют параллельные коннекты к
// выходной ноде (иначе при её недоступности сотни одновременных рукопожатий
// добивают и нас (пул обработчиков), и её (её strike-list).
func (u *UpstreamChain) upstreamMux() (*Mux, error) {
	deadline := time.Now().Add(20 * time.Second)
	for {
		if mx := u.getMux(); mx != nil && mx.Alive() {
			return mx, nil
		}
		if time.Now().After(deadline) {
			return nil, ErrChainDown
		}
		select {
		case <-u.stopCh:
			return nil, ErrChainDown
		case <-time.After(300 * time.Millisecond):
		}
	}
}

// Dial открывает TCP-поток к hostport ЧЕРЕЗ вышестоящую ноду. Домены из
// direct-списка идут напрямую (RU-локальные). Остальное — строго через
// цепочку; аплинк мёртв → ErrChainDown (fail-closed).
func (u *UpstreamChain) Dial(hostport string) (net.Conn, error) {
	if host, _, err := net.SplitHostPort(hostport); err == nil && u.matchDirect(host) {
		return net.DialTimeout("tcp", hostport, 10*time.Second)
	}
	mx, err := u.upstreamMux()
	if err != nil {
		return nil, err
	}
	var st *Stream
	if u.legacy.Load() {
		// Старая сборка выхода не знает RESOLVE: открываем legacy-кадром сразу,
		// домен резолвит её системный резолвер в момент дозвона.
		var enc []byte
		enc, err = EncodeTarget(hostport)
		if err == nil {
			st, err = mx.OpenRaw(enc)
		}
	} else {
		st, err = mx.Open(hostport)
	}
	if err != nil {
		u.reset()
		return nil, fmt.Errorf("chain: %w", err)
	}
	return &streamConn{Stream: st, peer: hostport}, nil
}

// DialUDP — UDP-associate через цепочку (OpenUDP на вышестоящей). UDP в
// direct-список не ходит: DNS/QUIC с IP входной ноды — это утечка.
func (u *UpstreamChain) DialUDP(hostport string) (net.Conn, error) {
	mx, err := u.upstreamMux()
	if err != nil {
		return nil, err
	}
	st, err := mx.OpenUDP(hostport)
	if err != nil {
		u.reset()
		return nil, fmt.Errorf("chain udp: %w", err)
	}
	return &streamConn{Stream: st, peer: hostport}, nil
}

// Close останавливает контур и рвёт аплинк.
func (u *UpstreamChain) Close() error {
	u.once.Do(func() { close(u.stopCh) })
	u.reset()
	u.wg.Wait()
	return nil
}

// streamConn адаптирует mux-Stream под net.Conn (дедлайны — no-op: у потока
// их нет, релейным циклам они не нужны).
type streamConn struct {
	*Stream
	peer string
}

func (c *streamConn) LocalAddr() net.Addr              { return chainAddr("chain") }
func (c *streamConn) RemoteAddr() net.Addr             { return chainAddr(c.peer) }
func (c *streamConn) SetDeadline(time.Time) error      { return nil }
func (c *streamConn) SetReadDeadline(time.Time) error  { return nil }
func (c *streamConn) SetWriteDeadline(time.Time) error { return nil }

type chainAddr string

func (a chainAddr) Network() string { return "cham-chain" }
func (a chainAddr) String() string  { return string(a) }
