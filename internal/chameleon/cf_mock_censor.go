package chameleon

// cf_mock_censor.go — MockCensor: a LAB/TEST-ONLY model of an on-path DPI
// middlebox (ТСПУ-like verdict function).
//
// It is an HTTP reverse proxy: client -> MockCensor -> upstream CAR node. For
// each request it computes a verdict:
//   - "clean": forward to upstream and return its response
//   - "block": return a synthetic block page (HTTP 403)
//   - "rst":   close the TCP connection to emulate injected RST
//
// A verdict is triggered when the request path or the upstream body contains
// one of the configured trigger signatures (default: the benign token
// CARForbiddenToken), so the node can encode bits as forbidden/clean resource
// states and the client recovers them from the censor's verdict. No real
// banned keywords or SNIs are used by default (safe-by-default).
//
// Stage A2/B5 additions (all deterministic, LAB/TEST ONLY):
//   - WithNoise: invert a fraction of verdicts (bit flips / dropped reads).
//   - WithRSTMode: deliver "block" verdicts as TCP RST instead of a 403 page
//     (многие реальные ТСПУ рвут соединение, а не показывают заглушку).
//   - WithVerdictDelay: случайная задержка вердикта 0..max — у реального
//     цензора тайминги плавают, и читатель обязан это терпеть.
//   - WithTriggerSignatures: набор сигнатур, на которые реагирует цензор
//     (конфигурация оператора в боевом мире).
//
// DO NOT use MockCensor in production. It exists only so the Control Fabric
// can be exercised end-to-end in a lab on a single host.

import (
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// MockCensor models an on-path DPI middlebox for lab testing.
type MockCensor struct {
	addr        string
	upstreamURL string
	blockPage   string

	mu  sync.Mutex // guards ln/srv (race-free Addr/Shutdown, go test -race)
	srv *http.Server
	ln  net.Listener

	noiseMu  sync.Mutex
	noise    *DRBG   // LAB ONLY: deterministic noise source (nil = no noise)
	flipFrac float64 // fraction of verdicts to invert
	delay    *DRBG   // LAB ONLY: verdict-latency source (nil = no extra delay)
	delayMax time.Duration

	rstMode bool     // deliver block verdicts as RST instead of 403 page
	sigs    []string // trigger signatures (default: [CARForbiddenToken])
}

// NewMockCensor creates a lab censor bound to addr, forwarding to upstreamURL.
func NewMockCensor(addr, upstreamURL, blockPage string) *MockCensor {
	if blockPage == "" {
		blockPage = "<html><title>blocked</title><body>blocked by policy</body></html>"
	}
	return &MockCensor{addr: addr, upstreamURL: upstreamURL, blockPage: blockPage}
}

// WithNoise makes the censor invert flipFrac of its verdicts (bit flips /
// dropped reads on the wire). Deterministic for a given seed, so noise tests
// are reproducible. LAB/TEST ONLY.
func (m *MockCensor) WithNoise(flipFrac float64, seed []byte) *MockCensor {
	m.noise = NewDRBG(seed, "mock-censor-noise")
	m.flipFrac = flipFrac
	return m
}

// WithRSTMode makes the censor deliver block verdicts as injected TCP RST
// (connection abort) instead of an HTTP 403 block page. LAB/TEST ONLY.
func (m *MockCensor) WithRSTMode(on bool) *MockCensor {
	m.rstMode = on
	return m
}

// WithVerdictDelay adds a random verdict latency in [0, maxDelay] before each
// response — реальные ТСПУ отвечают с плавающей задержкой. Deterministic for
// a given seed. LAB/TEST ONLY.
func (m *MockCensor) WithVerdictDelay(maxDelay time.Duration, seed []byte) *MockCensor {
	m.delay = NewDRBG(seed, "mock-censor-delay")
	m.delayMax = maxDelay
	return m
}

// WithTriggerSignatures задаёт набор сигнатур-триггеров цензора (в боевом
// мире — конфигурация оператора ноды). Пустой список возвращает дефолтный
// безобидный токен. LAB/TEST ONLY.
func (m *MockCensor) WithTriggerSignatures(sigs []string) *MockCensor {
	m.sigs = sigs
	return m
}

func (m *MockCensor) triggerHit(s string) bool {
	sigs := m.sigs
	if len(sigs) == 0 {
		sigs = []string{CARForbiddenToken}
	}
	for _, t := range sigs {
		if t != "" && strings.Contains(s, t) {
			return true
		}
	}
	return false
}

// draw returns the next noise sample in [0,1).
func (m *MockCensor) draw() float64 {
	m.noiseMu.Lock()
	defer m.noiseMu.Unlock()
	return float64(m.noise.Uint64()>>11) / float64(uint64(1)<<53)
}

// drawDelay returns the next verdict latency.
func (m *MockCensor) drawDelay() time.Duration {
	m.noiseMu.Lock()
	defer m.noiseMu.Unlock()
	return time.Duration(m.delay.Uint64() % uint64(m.delayMax+1))
}

// Serve starts the censor. Blocks until Shutdown.
func (m *MockCensor) Serve() error {
	ln, err := net.Listen("tcp", m.addr)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", m.handle)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	m.mu.Lock()
	m.ln = ln
	m.srv = srv
	m.mu.Unlock()
	return srv.Serve(ln)
}

func (m *MockCensor) handle(w http.ResponseWriter, r *http.Request) {
	blocked := false
	var body []byte
	// Rule 1: trigger signature in path
	if m.triggerHit(r.URL.Path) {
		blocked = true
	} else {
		// Rule 2: fetch upstream, inspect body
		req, _ := http.NewRequest(http.MethodGet, m.upstreamURL+r.URL.Path, nil)
		hc := &http.Client{Timeout: 3 * time.Second}
		resp, err := hc.Do(req)
		if err != nil {
			// unreachable upstream -> rst-like failure
			m.rst(w)
			return
		}
		body, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		if m.triggerHit(string(body)) {
			blocked = true
		}
	}
	// Stage A2: deterministic noise — invert a fraction of verdicts. A verdict
	// flipped to "clean" must not leak the trigger signature downstream, or the
	// reader would still see it in the body and read a 1.
	if m.noise != nil && m.flipFrac > 0 && m.draw() < m.flipFrac {
		blocked = !blocked
		body = []byte("ok")
	}
	// Stage B5: плавающая задержка вердикта.
	if m.delay != nil && m.delayMax > 0 {
		time.Sleep(m.drawDelay())
	}
	if blocked {
		if m.rstMode {
			m.rst(w)
		} else {
			m.block(w)
		}
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write(body)
}

func (m *MockCensor) block(w http.ResponseWriter) {
	b := []byte(m.blockPage)
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Content-Length", itoa(len(b)))
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write(b)
}

func (m *MockCensor) rst(w http.ResponseWriter) {
	// Emulate RST injection: hijack and hard-close the connection without a
	// valid HTTP response, so the client observes a reset/read error.
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "rst", http.StatusForbidden)
		return
	}
	conn, _, _ := hj.Hijack()
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetLinger(0) // настоящий RST, а не FIN
	}
	_ = conn.Close()
}

// Shutdown stops the censor.
func (m *MockCensor) Shutdown() error {
	m.mu.Lock()
	srv := m.srv
	m.mu.Unlock()
	if srv == nil {
		return nil
	}
	return srv.Close()
}

// Addr returns the listening address once Serve has bound the socket.
func (m *MockCensor) Addr() string {
	m.mu.Lock()
	ln := m.ln
	m.mu.Unlock()
	if ln == nil {
		return ""
	}
	return ln.Addr().String()
}
