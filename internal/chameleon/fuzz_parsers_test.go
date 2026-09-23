package chameleon

import (
	"encoding/base64"
	"testing"
)

func FuzzParseTarget(f *testing.F) {
	for _, target := range []string{"1.1.1.1:443", "[2001:4860:4860::8888]:53", "example.com:80"} {
		b, _ := EncodeTarget(target)
		f.Add(b)
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		parsed, err := ParseTarget(data)
		if err == nil {
			reencoded, err := EncodeTarget(parsed)
			if err != nil {
				t.Fatalf("accepted target cannot be encoded: %v", err)
			}
			if reparsed, err := ParseTarget(reencoded); err != nil || reparsed != parsed {
				t.Fatalf("non-canonical target round trip")
			}
		}
	})
}

func FuzzParseKeys(f *testing.F) {
	f.Add("")
	f.Add(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	f.Fuzz(func(t *testing.T, value string) {
		_, _ = ParseNodePubKey(value)
		_, _ = ParseNodePrivKey(value)
	})
}

func FuzzReadTransportFrame(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0})
	f.Fuzz(func(t *testing.T, wire []byte) {
		_, serverSession := deterministicSessions()
		conn, err := NewServerConn(newMemoryReader(wire), serverSession)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = conn.ReadMessage()
	})
}

func FuzzServerHandshakeParser(f *testing.F) {
	priv, _, err := GenerateNodeKey()
	if err != nil {
		f.Fatal(err)
	}
	staticPriv, err := ParseNodePrivKey(priv)
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte{})
	f.Add(make([]byte, clientHelloLen))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = ServerHandshake(newMemoryReader(data), staticPriv, nil)
	})
}
