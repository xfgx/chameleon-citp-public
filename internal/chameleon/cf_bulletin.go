package chameleon

// cf_bulletin.go — CDN / object-store "cache-state board" control channel.
//
// This is the only Control Fabric channel that carries actual (tiny, control
// only) message bytes. It is a store-and-forward board: the node publishes
// encrypted control frames (next-entry, carrier-profile, resume hints) under
// short-lived identifiers; the client polls them back as ordinary short HTTPS
// requests to a legitimate-looking host.
//
// Lab scope: the in-memory store is LOCAL DATA (see comments). In a real
// deployment the backend would be a CDN / object storage with rotating keys;
// that backend is NOT implemented here (would require owned CDN / S3-style
// credentials and is out of scope for the safe Control Fabric).

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// CDNCacheStateChannel is the node-side store-and-forward board.
type CDNCacheStateChannel struct {
	addr string
	cert *tls.Certificate // optional real TLS (self-signed for the bulletin endpoint)

	mu    sync.Mutex
	store map[string][][]byte // LOCAL DATA: in-memory control frames keyed by session id
	srv   *http.Server
	ln    net.Listener

	remote *RemoteBoard // optional external board mirror (CDN/R2 worker)
}

// NewCDNCacheStateChannel creates a node-side bulletin bound to addr (host:port).
func NewCDNCacheStateChannel(addr string) *CDNCacheStateChannel {
	return &CDNCacheStateChannel{addr: addr, store: make(map[string][][]byte)}
}

// WithRemoteBoard attaches an external board backend; every published frame
// is mirrored there (async, bounded, never blocking the data path).
func (c *CDNCacheStateChannel) WithRemoteBoard(b *RemoteBoard) *CDNCacheStateChannel {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.remote = b
	return c
}

// WithTLS enables real (self-signed) HTTPS. Pass the host to put in the cert.
func (c *CDNCacheStateChannel) WithTLS(host string) error {
	cert, err := SelfSignedTLSCert(host)
	if err != nil {
		return err
	}
	c.cert = &cert
	return nil
}

const (
	maxBulletinSessions = 4096 // cap on distinct session ids held in memory
	maxFramesPerSession = 64   // cap on queued frames per session id
)

// Publish stores an encrypted control frame for a session id.
// Frames live only in process memory and are lost on restart; the store is
// bounded so a misbehaving peer cannot exhaust node memory.
func (c *CDNCacheStateChannel) Publish(sessionID string, frame []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	frames := c.store[sessionID]
	if frames == nil && len(c.store) >= maxBulletinSessions {
		return // drop: too many distinct sessions
	}
	if len(frames) >= maxFramesPerSession {
		frames = frames[1:] // drop the oldest frame, keep the queue bounded
	}
	c.store[sessionID] = append(frames, frame)
	if c.remote != nil {
		c.remote.Enqueue(sessionID, frame)
	}
}

// Serve starts the HTTP board. Blocks until Shutdown.
func (c *CDNCacheStateChannel) Serve() error {
	ln, err := net.Listen("tcp", c.addr)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ingest/", c.handleIngest)
	mux.HandleFunc("/outbox/", c.handleOutbox)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	c.mu.Lock()
	c.ln = ln
	c.srv = srv
	cert := c.cert
	c.mu.Unlock()
	if cert != nil {
		srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{*cert}}
		return srv.ServeTLS(ln, "", "")
	}
	return srv.Serve(ln)
}

func (c *CDNCacheStateChannel) handleIngest(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/ingest/"):]
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxControlMessage+64))
	if err != nil {
		http.Error(w, "read failed", http.StatusBadRequest)
		return
	}
	if len(body) == 0 || len(body) > MaxControlMessage+64 {
		http.Error(w, "bad frame size", http.StatusRequestEntityTooLarge)
		return
	}
	c.Publish(id, body)
	_, _ = io.WriteString(w, "ack")
}

func (c *CDNCacheStateChannel) handleOutbox(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/outbox/"):]
	c.mu.Lock()
	frames := append([][]byte(nil), c.store[id]...)
	c.mu.Unlock()
	enc := make([]string, 0, len(frames))
	for _, f := range frames {
		enc = append(enc, base64.StdEncoding.EncodeToString(f))
	}
	_ = json.NewEncoder(w).Encode(enc)
}

// Shutdown stops the board.
func (c *CDNCacheStateChannel) Shutdown() error {
	c.mu.Lock()
	remote := c.remote
	srv := c.srv
	c.mu.Unlock()
	if remote != nil {
		remote.Close()
	}
	if srv == nil {
		return nil
	}
	return srv.Close()
}

// Addr returns the listening address once Serve has bound the socket.
func (c *CDNCacheStateChannel) Addr() string {
	c.mu.Lock()
	ln := c.ln
	c.mu.Unlock()
	if ln == nil {
		return ""
	}
	return ln.Addr().String()
}

// CDNCacheStateClient is the client-side poller.
type CDNCacheStateClient struct {
	baseURL string
	hc      *http.Client
}

// NewCDNCacheStateClient points at the board's base URL (scheme://host:port).
func NewCDNCacheStateClient(baseURL string) *CDNCacheStateClient {
	return &CDNCacheStateClient{
		baseURL: baseURL,
		hc:      &http.Client{Timeout: 5 * time.Second},
	}
}

// WithInsecureTLS enables HTTPS with self-signed cert verification skipped.
// Intended for the node's own self-signed TLS cert in a trusted deployment.
func (c *CDNCacheStateClient) WithInsecureTLS() *CDNCacheStateClient {
	c.hc = &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	return c
}

// Upload pushes an encrypted control frame to the board.
func (c *CDNCacheStateClient) Upload(sessionID string, frame []byte) error {
	req, _ := http.NewRequest(http.MethodPost, c.baseURL+"/ingest/"+sessionID, bytesReader(frame))
	req.Header.Set("User-Agent", boardUserAgent)
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errHTTPStatus(resp.StatusCode)
	}
	return nil
}

// Poll pulls all frames currently published for a session id.
func (c *CDNCacheStateClient) Poll(sessionID string) ([][]byte, error) {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+"/outbox/"+sessionID, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", boardUserAgent)
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errHTTPStatus(resp.StatusCode)
	}
	var encs []string
	if err := json.NewDecoder(resp.Body).Decode(&encs); err != nil {
		return nil, err
	}
	out := make([][]byte, 0, len(encs))
	for _, e := range encs {
		b, err := base64.StdEncoding.DecodeString(e)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

// bytesReader returns a Reader over a byte slice without importing bytes.
func bytesReader(b []byte) io.Reader { return &byteSliceReader{b: b} }

type byteSliceReader struct {
	b   []byte
	off int
}

func (r *byteSliceReader) Read(p []byte) (int, error) {
	if r.off >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.off:])
	r.off += n
	return n, nil
}

type httpStatusError int

func (e httpStatusError) Error() string { return "control-fabric: http status " + itoa(int(e)) }

func errHTTPStatus(code int) error { return httpStatusError(code) }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
