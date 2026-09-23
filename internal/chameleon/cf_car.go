package chameleon

// cf_car.go — Censor-as-Modulator (CAR) control channel.
//
// Concept (see protocol/control-fabric.md §3): the node writes bits by
// toggling a resource between a "forbidden" state (response body contains a
// benign trigger token; the on-path censor returns a 403 / RST verdict) and a
// "clean" state (normal 200). The client recovers bits from the observed
// verdict.
//
// Stage A (roadmap docs/ROADMAP-CENSOR-TRANSPORT.md):
//   - A1: window paths come from a DRBG codebook (cf_car_codebook.go), never
//     from sequential integers — both sides derive the book from the session
//     secret, nothing is negotiated on the wire.
//   - A2: bits are framed with SYNC + LEN + CRC-16 and a repetition FEC
//     (cf_car_fec.go); PublishFrame/ReadMessage carry whole control messages.
//   - A3: the reader paces probes with lognormal pauses (cf_car_pacer.go)
//     instead of the old fixed 150 ms/bit rhythm.
//
// SAFE BY DESIGN: the trigger token (CARForbiddenToken) is a benign string.
// No real banned keywords / SNIs are used and the channel carries only a few
// signaling bits (entry liveness, profile-switch ack). Real censor triggering
// depends on the actual on-path DPI rule set and is environment-specific; the
// lab uses MockCensor (cf_mock_censor.go, TEST/LAB ONLY).

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CARForbiddenToken is the benign trigger token used by the lab censor.
const CARForbiddenToken = "FORBIDDEN_TOKEN"

// CARChannel is the node-side verdict server.
type CARChannel struct {
	addr  string
	token string

	mu     sync.Mutex
	states map[string]uint8 // LOCAL DATA: window label -> verdict bit
	sigs   []string         // B1: trigger-контент по биту 1 (дефолт — benign token)
	srv    *http.Server
	ln     net.Listener
}

// NewCARChannel creates a node-side CAR server bound to addr (host:port).
func NewCARChannel(addr string) *CARChannel {
	return &CARChannel{addr: addr, token: CARForbiddenToken, states: make(map[string]uint8)}
}

// SetBit toggles a resource's state: 1 = forbidden, 0 = clean.
// Legacy lab form: window label is the decimal seq (kept for old tests).
func (c *CARChannel) SetBit(seq int, bit uint8) {
	c.SetBitLabel(strconv.Itoa(seq), bit)
}

// WithTriggerSignatures (этап B1, trigger-host): по биту 1 нода отвечает
// триггерным контентом из набора оператора вместо дефолтного benign-токена.
// Выбор сигнатуры детерминирован по метке окна (стабильно между перечитываниями).
// SAFE-BY-DEFAULT: без вызова этого метода нода отдаёт только CARForbiddenToken;
// настоящие сигнатуры — конфигурационные данные оператора, не код.
func (c *CARChannel) WithTriggerSignatures(sigs []string) *CARChannel {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sigs = sigs
	return c
}

// triggerBody выбирает триггерный контент для окна label.
func (c *CARChannel) triggerBody(label string) []byte {
	c.mu.Lock()
	sigs := c.sigs
	c.mu.Unlock()
	if len(sigs) == 0 {
		return []byte(c.token)
	}
	h := 0
	for i := 0; i < len(label); i++ {
		h = h*31 + int(label[i])
	}
	if h < 0 {
		h = -h
	}
	return []byte(sigs[h%len(sigs)])
}

// SetBitLabel toggles a codebook window by its DRBG-derived label.
func (c *CARChannel) SetBitLabel(label string, bit uint8) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if bit > 1 {
		bit = 1
	}
	c.states[label] = bit
}

// PublishFrame encodes msg as a Stage-A2 frame (SYNC+LEN+payload+CRC16,
// repetition FEC) and writes the bits onto the codebook windows in codebook
// order. The frame stays published until overwritten — readers may re-read
// windows after a CRC failure to get independent noise samples.
func (c *CARChannel) PublishFrame(book *CARCodebook, msg []byte, rep int) error {
	if book == nil {
		return errors.New("car: nil codebook")
	}
	bits := EncodeCARFrame(msg, rep)
	if bits == nil {
		return fmt.Errorf("car: payload exceeds %d bytes", CARMaxPayload)
	}
	if len(bits) > book.Windows() {
		return fmt.Errorf("car: codebook too small: need %d windows, have %d", len(bits), book.Windows())
	}
	for i, b := range bits {
		c.SetBitLabel(book.Label(i), b)
	}
	return nil
}

// Serve starts the HTTP server. Blocks until Shutdown.
func (c *CARChannel) Serve() error {
	ln, err := net.Listen("tcp", c.addr)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/car/", c.handle)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	c.mu.Lock()
	c.ln = ln
	c.srv = srv
	c.mu.Unlock()
	return srv.Serve(ln)
}

func (c *CARChannel) handle(w http.ResponseWriter, r *http.Request) {
	// /car/<label> — label is either a codebook token (Stage A1) or a legacy
	// decimal seq from the early lab code.
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 2 || parts[0] != "car" || parts[1] == "" {
		http.Error(w, "bad path", http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	bit := c.states[parts[1]]
	c.mu.Unlock()
	body := []byte("ok")
	if bit == 1 {
		body = c.triggerBody(parts[1])
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write(body)
}

// Shutdown stops the server.
func (c *CARChannel) Shutdown() error {
	c.mu.Lock()
	srv := c.srv
	c.mu.Unlock()
	if srv == nil {
		return nil
	}
	return srv.Close()
}

// Addr returns the listening address once Serve has bound the socket.
func (c *CARChannel) Addr() string {
	c.mu.Lock()
	ln := c.ln
	c.mu.Unlock()
	if ln == nil {
		return ""
	}
	return ln.Addr().String()
}

// CARReader recovers bits from the censor's verdict stream. It detects: 403,
// connection reset, timeout, the forbidden token, and configurable
// block-page signatures (real censor block-page HTML markers).
type CARReader struct {
	censorURL       string // URL of the on-path censor (or MockCensor in the lab)
	token           string
	blockSignatures []string // real block-page substrings to flag as verdict=1
	hc              *http.Client
	pacer           *CARPacer
}

// NewCARReader points at the censor's base URL. Stage A3: probes are paced
// with lognormal pauses (median 150 ms, sigma 0.6) instead of the old fixed
// 150 ms rhythm that our own query-cadence detector flagged.
func NewCARReader(censorURL string) *CARReader {
	return &CARReader{
		censorURL: strings.TrimRight(censorURL, "/"),
		token:     CARForbiddenToken,
		hc:        &http.Client{Timeout: 5 * time.Second},
		pacer:     NewCARPacer(150*time.Millisecond, 0.6),
	}
}

// WithBlockSignatures adds real block-page substrings to flag as verdict=1
// in addition to 403/RST/timeout/forbidden-token.
func (r *CARReader) WithBlockSignatures(sigs []string) *CARReader {
	r.blockSignatures = sigs
	return r
}

// WithPacer overrides the probe pacing (tests: fast deterministic pacers).
func (r *CARReader) WithPacer(p *CARPacer) *CARReader {
	r.pacer = p
	return r
}

// probe reads one verdict and then sleeps one paced pause.
func (r *CARReader) probe(path string) uint8 {
	v := r.verdict(path)
	r.pacer.Pause()
	return v
}

// verdict performs a single HTTP probe and maps the outcome to a bit:
// 1 = forbidden/blocked/rst/timeout, 0 = clean.
func (r *CARReader) verdict(path string) uint8 {
	resp, err := r.hc.Get(r.censorURL + path)
	if err != nil {
		// connection error / RST-like / timeout -> forbidden
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		return 1
	}
	buf := make([]byte, 512)
	n, _ := resp.Body.Read(buf)
	s := string(buf[:n])
	if strings.Contains(s, r.token) {
		return 1
	}
	for _, sig := range r.blockSignatures {
		if sig != "" && strings.Contains(s, sig) {
			return 1
		}
	}
	return 0
}

// ReadBit recovers one bit for a given legacy numeric seq.
func (r *CARReader) ReadBit(seq int) uint8 {
	return r.probe("/car/" + strconv.Itoa(seq))
}

// ReadBitLabel recovers one bit from a codebook window label.
func (r *CARReader) ReadBitLabel(label string) uint8 {
	return r.probe("/car/" + label)
}

// ReadBits reads count bits starting at start (legacy numeric windows).
func (r *CARReader) ReadBits(start, count int) []uint8 {
	out := make([]uint8, count)
	for i := 0; i < count; i++ {
		out[i] = r.ReadBit(start + i)
	}
	return out
}

// ReadMessage reads a Stage-A2 frame from the codebook: first the header
// windows (SYNC+LEN), then exactly as many windows as payload+CRC occupy.
// Returns ErrCARFrameCorrupt if the noise defeated the FEC on this attempt —
// the caller should re-read (the node keeps the frame published).
func (r *CARReader) ReadMessage(book *CARCodebook, rep int) ([]byte, error) {
	if book == nil {
		return nil, errors.New("car: nil codebook")
	}
	if rep <= 0 {
		rep = CARFrameRep
	}
	hdrWin := carFrameHeaderBits * rep
	if book.Windows() < hdrWin {
		return nil, errors.New("car: codebook smaller than frame header")
	}
	bits := make([]uint8, 0, hdrWin)
	for i := 0; i < hdrWin; i++ {
		bits = append(bits, r.ReadBitLabel(book.Label(i)))
	}
	plen, err := DecodeCARFrameHeader(bits, rep)
	if err != nil {
		return nil, err
	}
	totalWin := CARFrameWindows(plen, rep)
	if totalWin > book.Windows() {
		return nil, fmt.Errorf("car: codebook too small for payload %d bytes (need %d windows, have %d)", plen, totalWin, book.Windows())
	}
	for i := hdrWin; i < totalWin; i++ {
		bits = append(bits, r.ReadBitLabel(book.Label(i)))
	}
	return DecodeCARFrame(bits, rep)
}
