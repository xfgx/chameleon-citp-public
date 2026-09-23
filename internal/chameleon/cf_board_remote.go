package chameleon

// cf_board_remote.go — external bulletin board backend (CDN / object storage).
//
// The in-memory CDNCacheStateChannel keeps control frames in the node's
// process memory: if the node's IP is blocked, the board dies with it. A
// RemoteBoard mirrors every published frame to an EXTERNAL store-and-forward
// board (e.g. a Cloudflare Worker backed by R2) over ordinary HTTPS, so the
// control channel survives a full IP block of the node itself.
//
// Wire contract (must match the Worker script):
//
//	POST <base>/ingest/<sid>   Authorization: Bearer <token>  -> 200 "ack"
//	GET  <base>/outbox/<sid>   -> JSON array of base64-encoded frames
//
// The board only ever stores AEAD-encrypted frames (see PublishControl), so
// the CDN operator sees opaque ciphertext. The write token stays on the node
// (env CITP_CF_BOARD_TOKEN); clients need only the public base URL.
//
// NOTE: Cloudflare's Bot Fight Mode rejects the stock Go/Python HTTP client
// signature at the edge (error 1010), so all board requests carry a regular
// browser User-Agent.

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// boardUserAgent is sent on every board request; without it Cloudflare's bot
// filtering (edge error 1010) rejects the request before it reaches the Worker.
const boardUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

const (
	boardQueueDepth = 256 // bounded: frames awaiting upload
	boardWorkers    = 2   // concurrent upload goroutines
	boardAttempts   = 2   // per frame before counting as failed

	boardRetryPause = 500 * time.Millisecond
)

// RemoteBoard mirrors control frames to an external board over HTTPS.
// Uploads are asynchronous and bounded: board I/O must never stall the VPN
// data path (Publish is called during session setup).
type RemoteBoard struct {
	baseURL string
	token   string
	hc      *http.Client

	q      chan boardItem
	wg     sync.WaitGroup
	closed atomic.Bool

	enq     atomic.Uint64
	sent    atomic.Uint64
	failed  atomic.Uint64
	dropped atomic.Uint64
}

type boardItem struct {
	sessionID string
	frame     []byte
}

// NewRemoteBoard creates the mirror for a board base URL
// (e.g. "https://cham-bulletin.<acct>.workers.dev"). token is the board's
// write secret; pass "" only for a board that allows unauthenticated writes.
func NewRemoteBoard(baseURL, token string) *RemoteBoard {
	b := &RemoteBoard{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		hc:      &http.Client{Timeout: 8 * time.Second},
		q:       make(chan boardItem, boardQueueDepth),
	}
	b.wg.Add(boardWorkers)
	for i := 0; i < boardWorkers; i++ {
		go b.worker()
	}
	return b
}

// Enqueue schedules a frame for upload. Never blocks: when the queue is full
// the frame is dropped and counted (control frames are short-lived by design —
// the next session republishes fresh hints anyway).
//
// The Worker's sid rule is ^[A-Za-z0-9_-]{8,64}$; ControlSessionID output
// (22-char base64url) always satisfies it — short ad-hoc ids do not.
func (b *RemoteBoard) Enqueue(sessionID string, frame []byte) {
	defer func() { _ = recover() }() // send on closed channel after Close()
	if b.closed.Load() {
		return
	}
	select {
	case b.q <- boardItem{sessionID: sessionID, frame: append([]byte(nil), frame...)}:
		b.enq.Add(1)
	default:
		b.dropped.Add(1)
	}
}

func (b *RemoteBoard) worker() {
	defer b.wg.Done()
	for it := range b.q {
		ok := false
		for attempt := 0; attempt < boardAttempts; attempt++ {
			if attempt > 0 {
				time.Sleep(boardRetryPause)
			}
			if err := b.upload(it); err == nil {
				ok = true
				break
			}
		}
		if ok {
			b.sent.Add(1)
		} else {
			b.failed.Add(1)
		}
	}
}

func (b *RemoteBoard) upload(it boardItem) error {
	req, err := http.NewRequest(http.MethodPost, b.baseURL+"/ingest/"+it.sessionID, bytesReader(it.frame))
	if err != nil {
		return err
	}
	if b.token != "" {
		req.Header.Set("Authorization", "Bearer "+b.token)
	}
	req.Header.Set("User-Agent", boardUserAgent)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := b.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return errHTTPStatus(resp.StatusCode)
	}
	return nil
}

// Stats returns (enqueued, sent, failed, dropped) counters for logging/metrics.
func (b *RemoteBoard) Stats() (enqueued, sent, failed, dropped uint64) {
	return b.enq.Load(), b.sent.Load(), b.failed.Load(), b.dropped.Load()
}

// Close stops accepting frames and waits for queued uploads to finish.
// Idempotent.
func (b *RemoteBoard) Close() {
	if b.closed.CompareAndSwap(false, true) {
		close(b.q)
		b.wg.Wait()
	}
}
