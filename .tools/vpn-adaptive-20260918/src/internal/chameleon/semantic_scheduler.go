package chameleon

import (
	"errors"
	"net"
	"sync"
	"time"
)

var (
	ErrObjectExpired = errors.New("citp: object expired before transmission")
	ErrObjectSuperseded = errors.New("citp: queued latest-only object superseded")
	ErrSemanticQueueFull = errors.New("citp: latest-only queue limit reached")
)

const (
	paddingBurstBytes = 4096.0
	paddingIdleBytesPerSecond = 512.0
	paddingMaxBytesPerSecond = 8192.0
	paddingPayloadFraction = 0.05
	paddingQuietWindow = 10 * time.Millisecond
	maxPaddingPayload = 2048
	maxLatestPendingChannels = 256
)

type semanticChannel struct {
	stream uint32
	kind ObjectType
}

type latestPending struct {
	sequence uint64
	writers int
}

type trafficScheduler struct {
	mu sync.Mutex
	lastRefill time.Time
	credit float64
	ceiling float64
	latest map[semanticChannel]*latestPending
	chargedPadding uint64
}

func (s *trafficScheduler) refill(now time.Time) {
	if s.lastRefill.IsZero() {
		s.lastRefill = now
		s.credit, s.ceiling = paddingBurstBytes, paddingBurstBytes
		return
	}
	if now.Before(s.lastRefill) { return }
	seconds := now.Sub(s.lastRefill).Seconds()
	s.credit = min(paddingBurstBytes, s.credit+seconds*paddingIdleBytesPerSecond)
	s.ceiling = min(paddingBurstBytes, s.ceiling+seconds*paddingMaxBytesPerSecond)
	s.lastRefill = now
}

func (s *trafficScheduler) rewardPayload(now time.Time, bytes int) {
	if bytes <= 0 { return }
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refill(now)
	s.credit = min(paddingBurstBytes, s.credit+float64(bytes)*paddingPayloadFraction)
}

func (s *trafficScheduler) reservePadding(now time.Time, worstWireBytes int) bool {
	if worstWireBytes <= 0 || worstWireBytes > int(paddingBurstBytes) { return false }
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refill(now)
	cost := float64(worstWireBytes)
	if s.credit < cost || s.ceiling < cost { return false }
	s.credit -= cost
	s.ceiling -= cost
	s.chargedPadding += uint64(worstWireBytes)
	return true
}

func (s *trafficScheduler) beginLatest(key semanticChannel, sequence uint64) (*latestPending, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.latest == nil { s.latest = make(map[semanticChannel]*latestPending) }
	slot := s.latest[key]
	if slot == nil {
		if len(s.latest) >= maxLatestPendingChannels { return nil, ErrSemanticQueueFull }
		slot = &latestPending{}
		s.latest[key] = slot
	}
	slot.writers++
	slot.sequence = max(slot.sequence, sequence)
	return slot, nil
}

func (s *trafficScheduler) latestCurrent(slot *latestPending, sequence uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return sequence >= slot.sequence
}

func (s *trafficScheduler) finishLatest(key semanticChannel, slot *latestPending) {
	s.mu.Lock()
	defer s.mu.Unlock()
	slot.writers--
	if slot.writers == 0 { delete(s.latest, key) }
}

func (c *Conn) noteUsefulPayload(n int) {
	if n <= 0 { return }
	now := time.Now()
	c.lastUsefulSend.Store(now.UnixNano())
	c.traffic.rewardPayload(now, n)
}

// Optional padding never queues on sendMu and never consumes DRBG/nonce state
// when skipped. The budget is shared by every shaper on this connection.
func (c *Conn) TryWritePadding(n int) (bool, error) {
	if n < 0 { return false, errors.New("transport: negative padding size") }
	if c.closed.Load() { return false, net.ErrClosed }
	if c.pendingSend.Load() != 0 || !c.sendMu.TryLock() { return false, nil }
	defer c.sendMu.Unlock()
	if c.closed.Load() { return false, net.ErrClosed }
	now := time.Now()
	if c.pendingSend.Load() != 0 || now.Sub(time.Unix(0, c.lastUsefulSend.Load())) < paddingQuietWindow { return false, nil }
	n = min(n, maxPaddingPayload)
	// Charge an upper bound, including AEAD and randomized transport overhead.
	cost := 2 + c.prof.MinHeader + max(0, c.prof.HeaderVar-1) + 1 + n + c.sendAEAD.Overhead() + c.prof.MaxPad
	if !c.traffic.reservePadding(now, cost) { return false, nil }
	if err := c.writeFrameLocked(framePadding, make([]byte, n)); err != nil { return false, err }
	return true, nil
}

func (c *Conn) writeSemanticMessage(p []byte, obj *CITPObject) error {
	if len(p) > maxPayload { return errors.New("citp: object exceeds transport payload limit") }
	if obj.Mode < ModeReliableOrdered || obj.Mode > ModePartialReliable { return errors.New("citp: invalid delivery mode") }
	expired := func() bool { return obj.ExpiryUnixMs > 0 && time.Now().UnixMilli() >= obj.ExpiryUnixMs }
	if expired() { return ErrObjectExpired }
	c.pendingSend.Add(1)
	defer c.pendingSend.Add(-1)
	var slot *latestPending
	key := semanticChannel{stream: obj.StreamID, kind: obj.Type}
	if obj.Mode == ModeLatestOnly && obj.MonotonicSeq > 0 {
		var err error
		slot, err = c.traffic.beginLatest(key, obj.MonotonicSeq)
		if err != nil { return err }
		defer c.traffic.finishLatest(key, slot)
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	if c.closed.Load() { return net.ErrClosed }
	if expired() { return ErrObjectExpired }
	if slot != nil && !c.traffic.latestCurrent(slot, obj.MonotonicSeq) { return ErrObjectSuperseded }
	return c.writeFrameLocked(frameData, p)
}
