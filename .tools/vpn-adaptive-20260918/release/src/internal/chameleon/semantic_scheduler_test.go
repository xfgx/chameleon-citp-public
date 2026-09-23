package chameleon

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type adaptiveRecordingConn struct {
	writes atomic.Int64
	closed atomic.Bool
	short  bool
}

func (c *adaptiveRecordingConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *adaptiveRecordingConn) Write(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	c.writes.Add(1)
	if c.short {
		return len(b) - 1, nil
	}
	return len(b), nil
}
func (c *adaptiveRecordingConn) Close() error                   { c.closed.Store(true); return nil }
func (*adaptiveRecordingConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*adaptiveRecordingConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*adaptiveRecordingConn) SetDeadline(time.Time) error      { return nil }
func (*adaptiveRecordingConn) SetReadDeadline(time.Time) error  { return nil }
func (*adaptiveRecordingConn) SetWriteDeadline(time.Time) error { return nil }

func adaptiveTestConn(t *testing.T, raw net.Conn) *Conn {
	t.Helper()
	key := bytes.Repeat([]byte{7}, 32)
	conn, err := NewClientConn(raw, &Session{Seed: bytes.Repeat([]byte{3}, 32), SendKey: key, RecvKey: key})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func waitAdaptive(t *testing.T, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !ready() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestSemanticPaddingBudgetBounds(t *testing.T) {
	var budget trafficScheduler
	now := time.Unix(1_800_000_000, 0)
	count := 0
	for budget.reservePadding(now, 512) {
		count++
	}
	if count != 8 {
		t.Fatalf("startup burst %d", count)
	}
	if budget.reservePadding(now.Add(999*time.Millisecond), 512) {
		t.Fatal("idle budget refilled early")
	}
	if !budget.reservePadding(now.Add(time.Second), 512) {
		t.Fatal("idle budget did not refill")
	}
	budget.rewardPayload(now.Add(time.Second), 1<<30)
	count = 0
	for budget.reservePadding(now.Add(time.Second), 512) {
		count++
	}
	if count != 7 {
		t.Fatalf("shared hard ceiling not enforced: %d", count)
	}
	if budget.reservePadding(now, 512) {
		t.Fatal("backward clock created credit")
	}
}

func TestSemanticPaddingNeverQueuesOrConsumesNonceWhenSkipped(t *testing.T) {
	raw := &adaptiveRecordingConn{}
	conn := adaptiveTestConn(t, raw)
	conn.sendMu.Lock()
	sent, err := conn.TryWritePadding(100)
	conn.sendMu.Unlock()
	if sent || err != nil || conn.sendNonce != 0 {
		t.Fatalf("padding queued/consumed state: %v %v", sent, err)
	}
	conn.pendingSend.Add(1)
	sent, err = conn.TryWritePadding(100)
	conn.pendingSend.Add(-1)
	if sent || err != nil || raw.writes.Load() != 0 {
		t.Fatal("padding beat a pending payload")
	}
	conn.noteUsefulPayload(100)
	if sent, err := conn.TryWritePadding(100); sent || err != nil {
		t.Fatal("padding ignored useful-traffic quiet window")
	}
	if _, err := conn.TryWritePadding(-1); err == nil {
		t.Fatal("negative padding accepted")
	}
}

func TestSemanticExpiredFrameDoesNotAdvanceCryptoState(t *testing.T) {
	conn := adaptiveTestConn(t, &adaptiveRecordingConn{})
	obj := &CITPObject{Mode: ModeExpiring, ExpiryUnixMs: time.Now().Add(-time.Second).UnixMilli()}
	if err := conn.writeSemanticMessage([]byte("expired"), obj); !errors.Is(err, ErrObjectExpired) {
		t.Fatalf("expired error: %v", err)
	}
	if conn.sendNonce != 0 || conn.pendingSend.Load() != 0 {
		t.Fatal("expired object changed send state")
	}
}

func TestSemanticDeadlineRecheckedAfterQueueWait(t *testing.T) {
	conn := adaptiveTestConn(t, &adaptiveRecordingConn{})
	obj := &CITPObject{Mode: ModeExpiring, ExpiryUnixMs: time.Now().Add(40 * time.Millisecond).UnixMilli()}
	conn.sendMu.Lock()
	done := make(chan error, 1)
	go func() { done <- conn.writeSemanticMessage([]byte("deadline"), obj) }()
	waitAdaptive(t, func() bool { return conn.pendingSend.Load() == 1 })
	waitAdaptive(t, func() bool { return time.Now().UnixMilli() >= obj.ExpiryUnixMs })
	conn.sendMu.Unlock()
	if err := <-done; !errors.Is(err, ErrObjectExpired) {
		t.Fatalf("queued deadline ignored: %v", err)
	}
	if conn.sendNonce != 0 {
		t.Fatal("expired queued object advanced nonce")
	}
}

func TestSemanticLatestOnlyCoalescesQueuedUpdates(t *testing.T) {
	raw := &adaptiveRecordingConn{}
	conn := adaptiveTestConn(t, raw)
	conn.sendMu.Lock()
	results := make(chan error, 2)
	for _, sequence := range []uint64{1, 2} {
		go func(seq uint64) {
			results <- conn.writeSemanticMessage([]byte("state"), &CITPObject{Mode: ModeLatestOnly, Type: ObjTypeStreamChunk, StreamID: 5, MonotonicSeq: seq})
		}(sequence)
	}
	waitAdaptive(t, func() bool {
		conn.traffic.mu.Lock()
		defer conn.traffic.mu.Unlock()
		slot := conn.traffic.latest[semanticChannel{stream: 5, kind: ObjTypeStreamChunk}]
		return slot != nil && slot.writers == 2
	})
	conn.sendMu.Unlock()
	ok, replaced := 0, 0
	for range 2 {
		err := <-results
		if err == nil {
			ok++
		} else if errors.Is(err, ErrObjectSuperseded) {
			replaced++
		} else {
			t.Fatal(err)
		}
	}
	if ok != 1 || replaced != 1 || raw.writes.Load() != 1 || conn.sendNonce != 1 {
		t.Fatalf("coalescing result: ok=%d replaced=%d writes=%d nonce=%d", ok, replaced, raw.writes.Load(), conn.sendNonce)
	}
	if len(conn.traffic.latest) != 0 {
		t.Fatal("pending channel retained after completion")
	}
}

func TestSemanticReliableWritesAreNotCoalesced(t *testing.T) {
	raw := &adaptiveRecordingConn{}
	conn := adaptiveTestConn(t, raw)
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func(seq uint64) {
			defer wg.Done()
			if err := conn.writeSemanticMessage([]byte("reliable"), &CITPObject{Mode: ModeReliableOrdered, StreamID: 5, MonotonicSeq: seq}); err != nil {
				t.Error(err)
			}
		}(uint64(i))
	}
	wg.Wait()
	if raw.writes.Load() != 20 || conn.sendNonce != 20 {
		t.Fatal("reliable frames lost")
	}
}

func TestSemanticShortWriteClosesTransport(t *testing.T) {
	raw := &adaptiveRecordingConn{short: true}
	conn := adaptiveTestConn(t, raw)
	if err := conn.WriteMessage([]byte("payload")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write: %v", err)
	}
	if err := conn.WriteMessage([]byte("retry")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("partially written connection reused: %v", err)
	}
	if raw.writes.Load() != 1 {
		t.Fatal("connection reused after partial frame")
	}
}

func adaptivePipe(t *testing.T) (*Conn, *Conn) {
	t.Helper()
	a, b := net.Pipe()
	key := bytes.Repeat([]byte{7}, 32)
	s := &Session{Seed: bytes.Repeat([]byte{3}, 32), SendKey: key, RecvKey: key}
	client, err := NewClientConn(a, s)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServerConn(b, s)
	if err != nil {
		t.Fatal(err)
	}
	client.SetDeadline(time.Now().Add(5 * time.Second))
	server.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { client.Close(); server.Close() })
	return client, server
}

func TestSemanticPaddingKeepsReceiverSynchronized(t *testing.T) {
	client, server := adaptivePipe(t)
	readDone := make(chan error, 1)
	go func() {
		for i := range 32 {
			p, err := server.ReadMessage()
			if err != nil {
				readDone <- err
				return
			}
			if !bytes.Equal(p, []byte{byte(i)}) {
				readDone <- errors.New("payload order changed")
				return
			}
		}
		readDone <- nil
	}()
	if sent, err := client.TryWritePadding(100); err != nil || !sent {
		t.Fatalf("initial padding: %v %v", sent, err)
	}
	for i := range 32 {
		if err := client.WriteMessage([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
		if i < 31 {
			if _, err := client.TryWritePadding(100); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := <-readDone; err != nil {
		t.Fatal(err)
	}
}
