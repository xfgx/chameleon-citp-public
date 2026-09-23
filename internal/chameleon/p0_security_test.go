package chameleon

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"testing/quick"
	"time"
)

type memoryAddr string

func (a memoryAddr) Network() string { return "memory" }
func (a memoryAddr) String() string  { return string(a) }

type memoryConn struct {
	r      *bytes.Reader
	writes [][]byte
}

func newMemoryReader(b []byte) *memoryConn { return &memoryConn{r: bytes.NewReader(b)} }
func (c *memoryConn) Read(p []byte) (int, error) {
	if c.r == nil {
		return 0, io.EOF
	}
	return c.r.Read(p)
}
func (c *memoryConn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}
func (c *memoryConn) Close() error                     { return nil }
func (c *memoryConn) LocalAddr() net.Addr              { return memoryAddr("local") }
func (c *memoryConn) RemoteAddr() net.Addr             { return memoryAddr("remote") }
func (c *memoryConn) SetDeadline(time.Time) error      { return nil }
func (c *memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memoryConn) SetWriteDeadline(time.Time) error { return nil }

func deterministicSessions() (*Session, *Session) {
	seed := bytes.Repeat([]byte{0x31}, 32)
	a := bytes.Repeat([]byte{0x41}, 32)
	b := bytes.Repeat([]byte{0x42}, 32)
	return &Session{Seed: seed, SendKey: a, RecvKey: b}, &Session{Seed: seed, SendKey: b, RecvKey: a}
}

func recordedFrames(t *testing.T, messages ...[]byte) ([][]byte, *Session) {
	t.Helper()
	clientSession, serverSession := deterministicSessions()
	wire := &memoryConn{}
	conn, err := NewClientConn(wire, clientSession)
	if err != nil {
		t.Fatal(err)
	}
	for _, message := range messages {
		if err := conn.WriteMessage(message); err != nil {
			t.Fatal(err)
		}
	}
	return wire.writes, serverSession
}

func readServerFrame(t *testing.T, wire []byte, session *Session) ([]byte, error) {
	t.Helper()
	conn, err := NewServerConn(newMemoryReader(wire), session)
	if err != nil {
		t.Fatal(err)
	}
	return conn.ReadMessage()
}

func TestTransportRejectsCorruptionLossDuplicationAndReordering(t *testing.T) {
	frames, serverSession := recordedFrames(t, []byte("first"), []byte("second"))
	if len(frames) != 2 {
		t.Fatalf("expected two wire frames, got %d", len(frames))
	}

	corrupt := append([]byte(nil), frames[0]...)
	maskDRBG := NewDRBG(serverSession.Seed, "c2s-mask")
	_ = maskDRBG.Bytes(2)
	profile := NewProfile(serverSession.Seed)
	headerLen := profile.MinHeader + maskDRBG.Intn(profile.HeaderVar)
	_ = maskDRBG.Bytes(headerLen)
	ciphertextStart := 2 + headerLen
	if ciphertextStart >= len(corrupt) {
		t.Fatal("test frame has no ciphertext")
	}
	corrupt[ciphertextStart] ^= 0x80
	if _, err := readServerFrame(t, corrupt, serverSession); err == nil {
		t.Fatal("corrupted authenticated frame was accepted")
	}
	if _, err := readServerFrame(t, frames[1], serverSession); err == nil {
		t.Fatal("loss of the first frame did not desynchronize/auth-fail")
	}
	if _, err := readServerFrame(t, append(append([]byte{}, frames[1]...), frames[0]...), serverSession); err == nil {
		t.Fatal("reordered frames were accepted")
	}
	dupWire := append(append([]byte{}, frames[0]...), frames[0]...)
	conn, err := NewServerConn(newMemoryReader(dupWire), serverSession)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := conn.ReadMessage(); err != nil || string(got) != "first" {
		t.Fatalf("first frame failed: %q, %v", got, err)
	}
	if _, err := conn.ReadMessage(); err == nil {
		t.Fatal("duplicated frame was accepted with a new nonce")
	}
}

func TestNonceExhaustionFailsClosed(t *testing.T) {
	clientSession, serverSession := deterministicSessions()
	writer, err := NewClientConn(&memoryConn{}, clientSession)
	if err != nil {
		t.Fatal(err)
	}
	writer.sendNonce = math.MaxUint64
	if err := writer.WriteMessage([]byte("must fail")); err == nil {
		t.Fatal("send nonce wrapped instead of failing closed")
	}
	reader, err := NewServerConn(newMemoryReader(nil), serverSession)
	if err != nil {
		t.Fatal(err)
	}
	reader.recvNonce = math.MaxUint64
	if _, err := reader.ReadMessage(); err == nil {
		t.Fatal("receive nonce wrapped instead of failing closed")
	}
}

func TestTargetRoundTripProperty(t *testing.T) {
	property := func(ipRaw uint32, portRaw uint16) bool {
		port := portRaw
		if port == 0 {
			port = 1
		}
		ip := net.IPv4(byte(ipRaw>>24), byte(ipRaw>>16), byte(ipRaw>>8), byte(ipRaw))
		input := net.JoinHostPort(ip.String(), fmtUint16(port))
		encoded, err := EncodeTarget(input)
		if err != nil {
			return false
		}
		decoded, err := ParseTarget(encoded)
		return err == nil && decoded == input
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 2000}); err != nil {
		t.Fatal(err)
	}
}

func fmtUint16(v uint16) string {
	const digits = "0123456789"
	if v == 0 {
		return "0"
	}
	var b [5]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = digits[v%10]
		v /= 10
	}
	return string(b[i:])
}

func TestCITPRoundTripProperty(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	property := func(id, parent uint64, stream uint32, flags uint8, payload []byte) bool {
		if len(payload) > 2048 {
			payload = payload[:2048]
		}
		obj := &CITPObject{ObjectID: id, ParentID: parent, StreamID: stream, Type: ObjTypeStreamChunk, Mode: ModeReliableOrdered, Flags: flags, Payload: append([]byte(nil), payload...)}
		obj.Sign(key)
		decoded, err := DecodeCITPObject(obj.Encode())
		return err == nil && decoded.Verify(key) && reflect.DeepEqual(decoded.Payload, obj.Payload) && decoded.ObjectID == id && decoded.ParentID == parent && decoded.StreamID == stream
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 1000, MaxCountScale: 1}); err != nil {
		t.Fatal(err)
	}
}

func TestStrictParsersRejectTrailingData(t *testing.T) {
	target, _ := EncodeTarget("1.1.1.1:443")
	if _, err := ParseTarget(append(target, 0)); err == nil {
		t.Fatal("target parser accepted trailing data")
	}
	obj := &CITPObject{ObjectID: 1, Payload: []byte("x")}
	if _, err := DecodeCITPObject(append(obj.Encode(), 0)); err == nil {
		t.Fatal("CITP parser accepted trailing data")
	}
	var secret [32]byte
	ticket := NewMigrationTicket(1, 0, 0, time.Minute, secret)
	if _, err := DecodeMigrationTicket(append(ticket.Encode(), 0)); err == nil {
		t.Fatal("migration parser accepted trailing data")
	}
}

func TestReplayCacheIsBoundedAndFailsClosed(t *testing.T) {
	cache := newReplayCache()
	for i := 0; i < maxReplayEntries; i++ {
		var nonce [16]byte
		nonce[0] = byte(i >> 8)
		nonce[1] = byte(i)
		if cache.seenOrAdd(nonce, time.Hour) {
			t.Fatalf("fresh nonce %d rejected before cache reached its bound", i)
		}
	}
	var extra [16]byte
	extra[0], extra[1], extra[2] = 0xff, 0xff, 1
	if !cache.seenOrAdd(extra, time.Hour) {
		t.Fatal("full replay cache must fail closed")
	}
	if len(cache.seen) != maxReplayEntries {
		t.Fatalf("replay cache exceeded bound: %d", len(cache.seen))
	}
}

func TestMuxResourceLimits(t *testing.T) {
	m := newMux(nil)
	m.maxStreams = 2
	for i := uint32(1); i <= 2; i++ {
		if err := m.putStream(&Stream{m: m, id: i, inCh: make(chan []byte, streamQueueDepth)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.putStream(&Stream{m: m, id: 3, inCh: make(chan []byte, streamQueueDepth)}); err == nil {
		t.Fatal("stream limit was not enforced")
	}
	for i := 0; i < maxResolutionCache+10; i++ {
		m.cacheResolution(string(rune(i+1)), &ResolutionObject{Expiry: time.Now().Add(time.Hour).Unix()})
	}
	if len(m.resCache) > maxResolutionCache {
		t.Fatalf("resolution cache exceeded limit: %d", len(m.resCache))
	}
}

func TestPolicyIsCanonicalAndFailClosed(t *testing.T) {
	p := DefaultPolicy()
	p.AllowedDomains = []string{"example.com"}
	pe := NewPolicyEngine(p)
	for _, target := range []string{"127.0.0.1:80", "10.0.0.1:53", "[::1]:443", "100.64.0.1:443", "example.com:443", "missing-port"} {
		if decision, _ := pe.EvaluateOpen(target); decision != PolicyDeny {
			t.Fatalf("unsafe/unbound target allowed: %s", target)
		}
	}
	if decision, _ := pe.EvaluateResolve("evil-example.com"); decision != PolicyDeny {
		t.Fatal("domain suffix boundary bypassed allow-list")
	}
	if decision, _ := pe.EvaluateResolve("api.example.com"); decision != PolicyAllow {
		t.Fatal("valid subdomain rejected")
	}
	if decision, _ := pe.EvaluateOpen("1.1.1.1:443"); decision != PolicyAllow {
		t.Fatal("public IP should be allowed by default policy")
	}
}

func TestGoPythonCITPDifferential(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	obj := &CITPObject{ObjectID: 99, ParentID: 98, StreamID: 7, Type: ObjTypeStreamChunk, Mode: ModeReliableOrdered, Flags: 3, Offset: 123, ExpiryUnixMs: 456, MonotonicSeq: 789, Payload: []byte("go-python-differential")}
	obj.Sign(bytes.Repeat([]byte{9}, 32))
	encoded := obj.Encode()
	parser := filepath.Join("..", "..", "protocol", "reference_parser.py")
	out, err := exec.Command(python, parser, "--decode-hex", hex.EncodeToString(encoded)).Output()
	if err != nil {
		t.Fatalf("python parser: %v", err)
	}
	var got struct {
		ObjectID   uint64 `json:"object_id"`
		ParentID   uint64 `json:"parent_id"`
		StreamID   uint32 `json:"stream_id"`
		PayloadHex string `json:"payload_hex"`
		EncodedHex string `json:"encoded_hex"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got.ObjectID != obj.ObjectID || got.ParentID != obj.ParentID || got.StreamID != obj.StreamID || got.PayloadHex != hex.EncodeToString(obj.Payload) || got.EncodedHex != hex.EncodeToString(encoded) {
		t.Fatalf("Go/Python parser disagreement: %+v", got)
	}
}

var _ = errors.New
