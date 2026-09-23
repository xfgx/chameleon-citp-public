package chameleon

import (
	"context"
	"testing"
	"time"
)

func TestTTLSCarrierCapabilities(t *testing.T) {
	c := NewTTLSCarrier(TTLSConfig{Secret: "s", TTL: 8})
	caps := c.Capabilities()
	if caps.Name != "ttl-subhorizon" || c.Name() != "ttl-subhorizon" {
		t.Fatalf("имя carrier'а: %q", caps.Name)
	}
	if !caps.UnreliableDatagrams || caps.ReliableStreams {
		t.Fatal("TTLSCarrier обязан быть датаграммным и ненадёжным")
	}
	if caps.MaxFrameSize != TTLSMaxPayload {
		t.Fatalf("MaxFrameSize %d != %d", caps.MaxFrameSize, TTLSMaxPayload)
	}
}

func TestTTLSCarrierDialValidation(t *testing.T) {
	ctx := context.Background()
	if err := NewTTLSCarrier(TTLSConfig{TTL: 8}).Dial(ctx, "1.1.1.1:443"); err == nil {
		t.Fatal("Dial без секрета должен отклоняться")
	}
	if err := NewTTLSCarrier(TTLSConfig{Secret: "s"}).Dial(ctx, "1.1.1.1:443"); err == nil {
		t.Fatal("Dial без TTL должен отклоняться")
	}
	if err := NewTTLSCarrier(TTLSConfig{Secret: "s", TTL: 8}).Dial(ctx, "bad addr"); err == nil {
		t.Fatal("Dial с битым адресом должен отклоняться")
	}
}

// TestTTLSCarrierLoopback — carrier шлёт, TTLReceiver принимает: сквозная
// проверка интеграции Carrier-адаптера с библиотечным приёмником.
func TestTTLSCarrierLoopback(t *testing.T) {
	sm := fixedSmuggler(t)
	recv, err := NewTTLReceiver(sm, "127.0.0.1:0")
	if err != nil {
		t.Skipf("UDP недоступен в окружении: %v", err)
	}
	defer recv.Close()
	if err := recv.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}

	carrier := NewTTLSCarrier(TTLSConfig{
		Secret: "<REDACTED>",
		TTL:    64,
	})
	if err := carrier.Dial(context.Background(), recv.LocalAddr().String()); err != nil {
		t.Skipf("Dial: %v", err)
	}
	defer carrier.Close()

	if err := carrier.SendControl([]byte("control-msg")); err != nil {
		t.Fatalf("SendControl: %v", err)
	}
	if err := carrier.SendDatagram(7, []byte("datagram-msg")); err != nil {
		t.Fatalf("SendDatagram: %v", err)
	}

	fr1, err := recv.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	fr2, err := recv.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if string(fr1.Payload) != "control-msg" || string(fr2.Payload) != "datagram-msg" {
		t.Fatalf("payloads: %q / %q", fr1.Payload, fr2.Payload)
	}
	if fr1.Seq != 1 || fr2.Seq != 2 {
		t.Fatalf("seq: %d / %d — счётчик carrier'а должен быть монотонным", fr1.Seq, fr2.Seq)
	}
}
