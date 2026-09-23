package chameleon

// continuity_test.go — CST: криптография непрерывности: привязки CK,
// свежесть манифестов, поколения в тегах, доказательство владения секретом.

import (
	"bytes"
	"testing"
)

// CK привязан к клиенту, ноде, FlowID и цели: любая подмена -> другой ключ.
func TestContinuityBinding(t *testing.T) {
	secret := bytes.Repeat([]byte{7}, 32)
	cpub := bytes.Repeat([]byte{1}, 32)
	npub := bytes.Repeat([]byte{2}, 32)
	id := NewFlowID()
	base := DeriveContinuity(secret, cpub, npub, id, "tcp:example.com:443")
	same := DeriveContinuity(secret, cpub, npub, id, "tcp:example.com:443")
	if !bytes.Equal(base.DeltaKey(0, 1), same.DeltaKey(0, 1)) {
		t.Fatal("одинаковые входы -> разные CK")
	}
	diffClient := DeriveContinuity(secret, bytes.Repeat([]byte{9}, 32), npub, id, "tcp:example.com:443")
	diffNode := DeriveContinuity(secret, cpub, bytes.Repeat([]byte{8}, 32), id, "tcp:example.com:443")
	diffFlow := DeriveContinuity(secret, cpub, npub, NewFlowID(), "tcp:example.com:443")
	diffTarget := DeriveContinuity(secret, cpub, npub, id, "tcp:example.com:444")
	k := base.DeltaKey(0, 1)
	for i, fc := range []*FlowContinuity{diffClient, diffNode, diffFlow, diffTarget} {
		if bytes.Equal(k, fc.DeltaKey(0, 1)) {
			t.Fatalf("CK не привязан к измерению %d", i)
		}
	}
}

// Replay старого манифеста: MAC привязан к seed НОВОЙ физической сессии.
func TestAttachFreshness(t *testing.T) {
	secret := bytes.Repeat([]byte{3}, 32)
	fc := DeriveContinuity(secret, bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), NewFlowID(), "tcp:a:1")
	at := &CSTAttach{Version: 1, ID: fc.ID, NewGen: 2, ClientS2CAcked: 1, ExpiryMs: 1 << 40}
	sessA := []byte("session-A-fresh")
	sessB := []byte("session-B-other")
	dec, err := DecodeCSTAttach(at.Encode(fc, sessA))
	if err != nil {
		t.Fatal(err)
	}
	if !dec.VerifyMAC(fc, sessA) {
		t.Fatal("свежий манифест не прошёл")
	}
	if dec.VerifyMAC(fc, sessB) {
		t.Fatal("replay манифеста в другой сессии прошёл")
	}
	otherNode := DeriveContinuity(secret, bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{9}, 32), fc.ID, "tcp:a:1")
	if dec.VerifyMAC(otherNode, sessA) {
		t.Fatal("манифест принят с CK чужой ноды")
	}
}

// Теги дельт привязаны к направлению И поколению.
func TestDeltaTagGenBound(t *testing.T) {
	secret := bytes.Repeat([]byte{5}, 32)
	fc := DeriveContinuity(secret, bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), NewFlowID(), "tcp:b:2")
	d := &CSTDelta{Version: 1, ID: fc.ID, Dir: CSTDirC2S, Gen: 2, Offset: 1, Dep: 1, Payload: []byte("x")}
	dec, err := DecodeCSTDelta(d.Encode(fc))
	if err != nil {
		t.Fatal(err)
	}
	if !dec.VerifyTag(fc) {
		t.Fatal("своя дельта не прошла")
	}
	dec.Gen = 1 // подмена поколения
	if dec.VerifyTag(fc) {
		t.Fatal("дельта старого поколения прошла HMAC")
	}
	dec.Gen = 2
	dec.Dir = CSTDirS2C // подмена направления
	if dec.VerifyTag(fc) {
		t.Fatal("дельта чужого направления прошла HMAC")
	}
}

// KnowledgeOpen: MAC доказывает владение FlowSecret.
func TestOpenProof(t *testing.T) {
	var secret [32]byte
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	id := NewFlowID()
	o := &CSTOpen{Version: CSTVersion, ID: id, Secret: secret, Mode: CSTModeTCP, Target: []byte{1, 2, 3}}
	enc := o.Encode()
	if _, err := DecodeCSTOpen(enc); err != nil {
		t.Fatal(err)
	}
	o2 := &CSTOpen{Version: CSTVersion, ID: id, Mode: CSTModeTCP, Target: []byte{1, 2, 3}} // другой секрет
	enc2 := o2.Encode()
	mixed := append(enc[:len(enc)-32], enc2[len(enc2)-32:]...)
	if _, err := DecodeCSTOpen(mixed); err == nil {
		t.Fatal("подмена тела с чужим MAC принята")
	}
}

// Zeroize затирает CK: производные ключи меняются; идемпотентно.
func TestContinuityZeroize(t *testing.T) {
	secret := bytes.Repeat([]byte{4}, 32)
	fc := DeriveContinuity(secret, bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), NewFlowID(), "tcp:c:3")
	before := append([]byte(nil), fc.DeltaKey(0, 1)...)
	fc.Zeroize()
	if bytes.Equal(before, fc.DeltaKey(0, 1)) {
		t.Fatal("Zeroize не затёр CK")
	}
	fc.Zeroize()
}
