package chameleon

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func legacyResolutionData(r *ResolutionObject) []byte {
	b := []byte(r.Domain)
	for _, addr := range r.Addrs { b = append(b, addr...) }
	return binary.BigEndian.AppendUint64(b, uint64(r.Expiry))
}

func TestResolutionCanonicalRejectsBoundaryCollision(t *testing.T) {
	seed := []byte("test-session-seed")
	expiry := time.Now().Add(time.Minute).Unix()
	a := &ResolutionObject{Domain: "example.test", Addrs: []string{"1.1.1.1", "11.1.1.1"}, Expiry: expiry}
	b := &ResolutionObject{Domain: "example.test", Addrs: []string{"1.1.1.11", "1.1.1.1"}, Expiry: expiry}
	if !bytes.Equal(legacyResolutionData(a), legacyResolutionData(b)) { t.Fatal("fixture is not a legacy boundary collision") }
	a.Sign(seed)
	b.Sig = append([]byte(nil), a.Sig...)
	if b.Verify(seed) == nil { t.Fatal("altered address boundaries accepted") }
	b.Sign(seed)
	if bytes.Equal(a.Sig, b.Sig) { t.Fatal("canonical signatures collide") }
	decoded, err := DecodeResolutionObject(a.Encode())
	if err != nil || decoded.Verify(seed) != nil { t.Fatalf("canonical roundtrip failed: %v", err) }
}

func TestResolutionCanonicalNoLegacySignatureFallback(t *testing.T) {
	seed := []byte("test-session-seed")
	ro := &ResolutionObject{Domain: "example.test", Addrs: []string{"1.1.1.1"}, Expiry: time.Now().Add(time.Minute).Unix()}
	ro.Sig = hmacSHA256(seed, legacyResolutionData(ro))
	if ro.Verify(seed) == nil { t.Fatal("legacy HMAC silently accepted") }
}

func TestResolutionIssuanceRejectsClientMintedObject(t *testing.T) {
	seed := []byte("known-to-both-peers")
	now := time.Now()
	ro := &ResolutionObject{Domain: "example.test", Addrs: []string{"1.1.1.1"}, Expiry: now.Add(time.Minute).Unix()}
	ro.Sign(seed)
	if ro.Verify(seed) != nil { t.Fatal("fixture HMAC invalid") }
	var issued resolutionIssuance
	if issued.verify(ro, now) == nil { t.Fatal("shared-key HMAC mistaken for server issuance") }
	if err := issued.remember(ro, now); err != nil { t.Fatal(err) }
	if err := issued.verify(ro, now); err != nil { t.Fatal(err) }
	ro.Addrs[0] = "8.8.8.8"
	ro.Sign(seed)
	if issued.verify(ro, now) == nil { t.Fatal("client re-signed modified object accepted") }
}

func TestResolutionIssuanceBoundedAndExpiry(t *testing.T) {
	var issued resolutionIssuance
	now := time.Now()
	makeRO := func(i int, expiry time.Time) *ResolutionObject {
		ro := &ResolutionObject{Domain: fmt.Sprintf("node-%d.test", i), Addrs: []string{"1.1.1.1"}, Expiry: expiry.Unix()}
		ro.Sign([]byte("seed"))
		return ro
	}
	for i := range maxIssuedResolutions {
		if err := issued.remember(makeRO(i, now.Add(time.Minute)), now); err != nil { t.Fatal(err) }
	}
	if issued.remember(makeRO(maxIssuedResolutions, now.Add(time.Minute)), now) == nil { t.Fatal("issuance cache limit not enforced") }
	future := now.Add(2*time.Minute)
	if err := issued.remember(makeRO(maxIssuedResolutions, future.Add(time.Minute)), future); err != nil { t.Fatal(err) }
	if len(issued.objects) != 1 { t.Fatal("expired issuances not collected") }
}

func TestResolutionOpenNeverDowngradesErrors(t *testing.T) {
	for _, mode := range []string{"policy", "bad-signature", "wrong-domain", "open-auth-denied", "explicit-upstream"} {
		t.Run(mode, func(t *testing.T) {
			clientConn, serverConn := adaptivePipe(t)
			server := newMux(serverConn)
			var legacyOpens atomic.Int64
			server.onResolve = func(m *Mux, sid uint32, domain string) {
				if mode == "policy" { _ = m.send(sid, smResolveErr, []byte("policy deny: test")); return }
				if mode == "explicit-upstream" { _ = m.send(sid, smResolveErr, []byte(errResolveViaUpstream.Error())); return }
				ro := &ResolutionObject{Domain: domain, Addrs: []string{"1.1.1.1"}, Expiry: time.Now().Add(time.Minute).Unix()}
				if mode == "wrong-domain" { ro.Domain = "other.test" }
				ro.Sign(serverConn.seed)
				if mode == "bad-signature" { ro.Sig[0] ^= 1 }
				_ = m.send(sid, smResolveOK, ro.Encode())
			}
			server.onOpenAuth = func(m *Mux, sid uint32, _ []byte) { _ = m.send(sid, smOpenErr, []byte("open-auth: denied")) }
			server.onOpen = func(m *Mux, sid uint32, _ []byte) { legacyOpens.Add(1); _ = m.send(sid, smOpenOK, nil) }
			go server.loop()
			client := NewMuxClient(clientConn)
			stream, err := client.Open("example.test:443")
			if mode == "explicit-upstream" {
				if err != nil || stream == nil || legacyOpens.Load() != 1 { t.Fatalf("explicit authenticated delegation failed: %v", err) }
			} else if err == nil || legacyOpens.Load() != 0 {
				t.Fatalf("%s error downgraded: err=%v legacy=%d", mode, err, legacyOpens.Load())
			}
		})
	}
}

func TestResolutionMalformedCannotBeSigned(t *testing.T) {
	ro := &ResolutionObject{Domain: "example.test", Addrs: nil, Expiry: time.Now().Add(time.Minute).Unix()}
	ro.Sign([]byte("seed"))
	if ro.Encode() != nil || ro.Verify([]byte("seed")) == nil { t.Fatal("empty address set accepted") }
	var nilRO *ResolutionObject
	if nilRO.Verify([]byte("seed")) == nil { t.Fatal("nil object accepted") }
}
