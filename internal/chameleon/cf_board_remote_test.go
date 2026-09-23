package chameleon

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockWorker emulates the Cloudflare Worker + R2 board contract:
// POST /ingest/<sid> with Bearer auth, GET /outbox/<sid> returns a JSON
// array of base64-encoded frames.
type mockWorker struct {
	mu       sync.Mutex
	frames   map[string][][]byte
	token    string
	uaSeen   string
	authSeen string
}

func (m *mockWorker) handler(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 2 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	kind, sid := parts[0], parts[1]
	switch {
	case kind == "ingest" && r.Method == http.MethodPost:
		if r.Header.Get("Authorization") != "Bearer "+m.token {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 2048))
		if err != nil || len(body) == 0 {
			http.Error(w, "bad frame", http.StatusBadRequest)
			return
		}
		m.mu.Lock()
		m.frames[sid] = append(m.frames[sid], body)
		m.uaSeen = r.Header.Get("User-Agent")
		m.authSeen = r.Header.Get("Authorization")
		m.mu.Unlock()
		_, _ = io.WriteString(w, "ack")
	case kind == "outbox" && r.Method == http.MethodGet:
		m.mu.Lock()
		enc := make([]string, 0, len(m.frames[sid]))
		for _, f := range m.frames[sid] {
			enc = append(enc, base64.StdEncoding.EncodeToString(f))
		}
		m.mu.Unlock()
		_ = json.NewEncoder(w).Encode(enc)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func newMockWorker(t *testing.T, token string) (*mockWorker, *httptest.Server) {
	t.Helper()
	mw := &mockWorker{frames: map[string][][]byte{}, token: token}
	ts := httptest.NewServer(http.HandlerFunc(mw.handler))
	t.Cleanup(ts.Close)
	return mw, ts
}

// Publish on the node channel must be mirrored to the external board with
// the write token and a browser User-Agent (Cloudflare bot filter).
func TestRemoteBoardMirrorPublish(t *testing.T) {
	mw, ts := newMockWorker(t, "sekret")

	cdn := NewCDNCacheStateChannel("127.0.0.1:0") // local board, no Serve needed
	rb := NewRemoteBoard(ts.URL, "sekret")
	cdn.WithRemoteBoard(rb)
	defer rb.Close()

	cdn.Publish("sessX", []byte("frame-1"))

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mw.mu.Lock()
		n := len(mw.frames["sessX"])
		mw.mu.Unlock()
		if n == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	mw.mu.Lock()
	got := mw.frames["sessX"]
	ua := mw.uaSeen
	auth := mw.authSeen
	mw.mu.Unlock()

	if len(got) != 1 || string(got[0]) != "frame-1" {
		t.Fatalf("remote board did not receive frame: %v", got)
	}
	if auth != "Bearer sekret" {
		t.Fatalf("missing/wrong auth header: %q", auth)
	}
	if !strings.HasPrefix(ua, "Mozilla/5.0") {
		t.Fatalf("missing browser User-Agent, got %q", ua)
	}

	cdn.mu.Lock()
	localN := len(cdn.store["sessX"])
	cdn.mu.Unlock()
	if localN != 1 {
		t.Fatal("local store lost the frame")
	}

	// The mock handler stores the frame before the "ack" round-trip
	// completes, so wait for the worker goroutine to settle the counters.
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if rb.sent.Load()+rb.failed.Load() == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, sent, failed, _ := rb.Stats()
	if failed != 0 || sent != 1 {
		t.Fatalf("stats sent=%d failed=%d, want 1/0", sent, failed)
	}
}

// A wrong write token must be rejected (403) and counted as failed.
func TestRemoteBoardAuthRejected(t *testing.T) {
	_, ts := newMockWorker(t, "right")
	rb := NewRemoteBoard(ts.URL, "wrong")
	defer rb.Close()

	rb.Enqueue("sessY", []byte("x"))

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if rb.failed.Load() == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("expected failed=1 for rejected token")
}

// The existing CDN client must poll the worker's JSON contract unchanged.
func TestCDNClientAgainstWorkerContract(t *testing.T) {
	mw := &mockWorker{frames: map[string][][]byte{"sessZ": {[]byte("a"), []byte("b")}}, token: "t"}
	ts := httptest.NewServer(http.HandlerFunc(mw.handler))
	defer ts.Close()

	cli := NewCDNCacheStateClient(ts.URL)
	got, err := cli.Poll("sessZ")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || string(got[0]) != "a" || string(got[1]) != "b" {
		t.Fatalf("bad poll: %v", got)
	}
}

// Close is idempotent; Enqueue after Close must not panic.
func TestRemoteBoardCloseIdempotent(t *testing.T) {
	rb := NewRemoteBoard("http://127.0.0.1:1", "t")
	rb.Close()
	rb.Close()
	rb.Enqueue("sessW", []byte("x"))
}
