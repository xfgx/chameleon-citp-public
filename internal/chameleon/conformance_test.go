package chameleon

import (
	"crypto/rand"
	"io"
	"testing"
	"time"
)

// FuzzDecodeCITPObject проверяет устойчивость декодера к произвольным битым данным.
func FuzzDecodeCITPObject(f *testing.F) {
	// Добавляем валидные seed-векторы в корпус
	obj := &CITPObject{
		ObjectID:     12345,
		ParentID:     12344,
		StreamID:     7,
		Type:         ObjTypeIntentOpen,
		Mode:         ModeReliableOrdered,
		Offset:       2048,
		ExpiryUnixMs: 1800000000,
		MonotonicSeq: 10,
		Payload:      []byte("fuzz-seed-payload-citp"),
	}
	f.Add(obj.Encode())
	f.Add([]byte{})
	f.Add(make([]byte, 42))

	f.Fuzz(func(t *testing.T, data []byte) {
		res, err := DecodeCITPObject(data)
		if err == nil && res != nil {
			// Проверяем, что повторная сериализация не вызывает панику
			_ = res.Encode()
			_ = res.IsExpired(time.Now().UnixMilli())
		}
	})
}

// FuzzDecodeResolutionObject проверяет декодер DNS Resolution объектов.
func FuzzDecodeResolutionObject(f *testing.F) {
	ro := &ResolutionObject{
		Domain: "example.com",
		Addrs:  []string{"93.184.216.34", "93.184.216.35"},
		Expiry: 1800000000,
		Sig:    make([]byte, 32),
	}
	f.Add(ro.Encode())
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		res, err := DecodeResolutionObject(data)
		if err == nil && res != nil {
			_ = res.Encode()
			_ = res.MatchHost("example.com")
		}
	})
}

// FuzzDecodeMigrationTicket проверяет парсер тикетов миграции.
func FuzzDecodeMigrationTicket(f *testing.F) {
	var secret [32]byte
	ticket := NewMigrationTicket(1, 100, 100, time.Hour, secret)
	f.Add(ticket.Encode())
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		res, err := DecodeMigrationTicket(data)
		if err == nil && res != nil {
			_ = res.Encode()
		}
	})
}

// Conformance Test: Инварианты I1..I10
func TestConformanceInvariants(t *testing.T) {
	seed := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, seed)

	// I1 & I2: AuthTag и Expiry
	obj := &CITPObject{
		ObjectID:     1,
		StreamID:     1,
		Type:         ObjTypeStreamChunk,
		Mode:         ModeExpiring,
		ExpiryUnixMs: time.Now().Add(-1 * time.Second).UnixMilli(),
		Payload:      []byte("data"),
	}
	obj.Sign(seed)

	if !obj.Verify(seed) {
		t.Fatal("I1 Violation: Подпись объекта должна валидироваться")
	}
	if !obj.IsExpired(time.Now().UnixMilli()) {
		t.Fatal("I2 Violation: Просроченный объект обязан распознаваться")
	}

	// I5: DNS Binding & Anti-SSRF
	pe := NewPolicyEngine(DefaultPolicy())
	dec, reason := pe.EvaluateOpen("127.0.0.1:80")
	if dec != PolicyDeny {
		t.Fatalf("I5/Anti-SSRF Violation: loopback должен быть отклонен (got %s, reason: %s)", dec, reason)
	}

	decPrivate, _ := pe.EvaluateOpen("192.168.1.1:443")
	if decPrivate != PolicyDeny {
		t.Fatal("I5/Anti-SSRF Violation: приватная сеть 192.168.x.x обязана быть отклонена")
	}

	decValid, _ := pe.EvaluateOpen("1.1.1.1:443")
	if decValid != PolicyAllow {
		t.Fatal("Публичный адрес 1.1.1.1:443 должен быть разрешен")
	}
}

// Conformance Test: Signed Node Directory Federation
func TestSignedNodeDirectoryFederation(t *testing.T) {
	masterKey := []byte("provider-master-secret-key-32b!")
	dir := &SignedNodeDirectory{
		TenantID:         "tenant-alpha",
		ServiceID:        "citp-service-main",
		DirectoryVersion: 1,
		ExpiresAt:        time.Now().Add(24 * time.Hour).Unix(),
		Nodes: []NodeDescriptor{
			{
				NodeID:       "node-eu-1",
				Address:      "198.51.100.10:8443",
				PubKey:       "test-pubkey",
				Capabilities: []string{"tcp", "dns-binding", "resume"},
				Weight:       100,
				Region:       "eu-central",
			},
		},
	}

	dir.Sign(masterKey)

	if err := dir.Verify(masterKey, time.Now().Unix()); err != nil {
		t.Fatalf("верификация директории провайдера провалена: %v", err)
	}

	wrongKey := []byte("alien-provider-secret-key-32b!")
	if err := dir.Verify(wrongKey, time.Now().Unix()); err == nil {
		t.Fatal("директория не должна верифицироваться чужим ключом провайдера")
	}
}
