package chameleon

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func fixedSmuggler(t *testing.T) *TTLSmuggler {
	t.Helper()
	sm, err := NewTTLSmuggler("chameleon-subhorizon-ttl-shared-secret-v1")
	if err != nil {
		t.Fatal(err)
	}
	return sm
}

func TestTTLSRoundTrip(t *testing.T) {
	sm := fixedSmuggler(t)
	sizes := []int{0, 1, 12, 100, 1400, TTLSMaxPayload}
	for i, n := range sizes {
		payload := bytes.Repeat([]byte{byte(i)}, n)
		frame, err := sm.Encrypt(uint64(i+1), payload)
		if err != nil {
			t.Fatalf("size %d: encrypt: %v", n, err)
		}
		if len(frame) != TTLSHeaderSize+n+TTLSTagSize {
			t.Fatalf("size %d: длина кадра %d", n, len(frame))
		}
		seq, pt, err := sm.Decrypt(frame)
		if err != nil {
			t.Fatalf("size %d: decrypt: %v", n, err)
		}
		if seq != uint64(i+1) {
			t.Fatalf("size %d: seq %d", n, seq)
		}
		if !bytes.Equal(pt, payload) {
			t.Fatalf("size %d: payload не совпал", n)
		}
	}
}

func TestTTLSPayloadTooBig(t *testing.T) {
	sm := fixedSmuggler(t)
	if _, err := sm.Encrypt(1, make([]byte, TTLSMaxPayload+1)); err == nil {
		t.Fatal("переполнение полезной нагрузки должно отклоняться")
	}
}

func TestTTLSBadMagic(t *testing.T) {
	sm := fixedSmuggler(t)
	frame, err := sm.Encrypt(1, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	frame[0] ^= 0xFF
	if _, _, err := sm.Decrypt(frame); err == nil {
		t.Fatal("битый magic должен отклоняться")
	}
}

func TestTTLSTruncated(t *testing.T) {
	sm := fixedSmuggler(t)
	frame, err := sm.Encrypt(1, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 3, TTLSHeaderSize - 1, TTLSHeaderSize, TTLSHeaderSize + TTLSTagSize - 1} {
		if _, _, err := sm.Decrypt(frame[:n]); err == nil {
			t.Fatalf("усечение до %d байт должно отклоняться", n)
		}
	}
}

func TestTTLSTamperedCiphertext(t *testing.T) {
	sm := fixedSmuggler(t)
	frame, err := sm.Encrypt(1, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	frame[len(frame)-1] ^= 0x01
	if _, _, err := sm.Decrypt(frame); err == nil {
		t.Fatal("изменённый шифротекст должен отклоняться GCM")
	}
	// подмена seq: он входит в AAD, поэтому тоже ломает GCM
	frame2, err := sm.Encrypt(7, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	frame2[11] ^= 0x01
	if _, _, err := sm.Decrypt(frame2); err == nil {
		t.Fatal("изменённый seq должен отклоняться (AAD)")
	}
}

func TestTTLSWrongKey(t *testing.T) {
	a := fixedSmuggler(t)
	b, err := NewTTLSmuggler("совершенно другой секрет")
	if err != nil {
		t.Fatal(err)
	}
	frame, err := a.Encrypt(1, []byte("secret-data"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Decrypt(frame); err == nil {
		t.Fatal("чужой ключ не должен расшифровывать кадр")
	}
}

func TestTTLSMaxPayloadConstant(t *testing.T) {
	// UDP payload <= 65507 (65535 - 20 IP - 8 UDP)
	if TTLSMaxPayload != 65507-TTLSHeaderSize-TTLSTagSize {
		t.Fatal("константа TTLSMaxPayload рассогласована")
	}
	if TTLSMaxPayload <= 0 {
		t.Fatal("TTLSMaxPayload должен быть положительным")
	}
}

// TestTTLSUDPLoopback — сквозная проверка: реальный UDP на loopback, сокетный
// TTL и разбор кадров. На loopback TTL не расходуется, поэтому пакеты доходят.
func TestTTLSUDPLoopback(t *testing.T) {
	sm := fixedSmuggler(t)
	recv, err := NewTTLReceiver(sm, "127.0.0.1:0")
	if err != nil {
		t.Skipf("UDP недоступен в окружении: %v", err)
	}
	defer recv.Close()
	sender, err := NewTTLSender(sm, recv.LocalAddr().String(), 64)
	if err != nil {
		t.Skipf("не удалось выставить TTL: %v", err)
	}
	defer sender.Close()
	if err := recv.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}

	const count = 3
	for i := 1; i <= count; i++ {
		if _, err := sender.Send(uint64(i), []byte("frame-payload")); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	for i := 1; i <= count; i++ {
		fr, err := recv.ReadFrame()
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if fr.Seq != uint64(i) || string(fr.Payload) != "frame-payload" {
			t.Fatalf("кадр %d: seq=%d payload=%q", i, fr.Seq, fr.Payload)
		}
		if fr.Size != TTLSHeaderSize+len("frame-payload")+TTLSTagSize {
			t.Fatalf("кадр %d: размер на проводе %d", i, fr.Size)
		}
	}
}

// TestTTLSEchoLoopback — двусторонний обмен по модели клиент<->сервер:
// клиент шлёт кадр голым UDP-сокетом, приёмник отвечает эхом через SendTo,
// клиент читает и расшифровывает ответ со своего сокета.
func TestTTLSEchoLoopback(t *testing.T) {
	sm := fixedSmuggler(t)
	recv, err := NewTTLReceiver(sm, "127.0.0.1:0")
	if err != nil {
		t.Skipf("UDP недоступен в окружении: %v", err)
	}
	defer recv.Close()
	if err := recv.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}

	// «клиент» — отдельный UDP-сокет, как у реального устройства
	cli, err := net.ListenUDP("udp4", nil)
	if err != nil {
		t.Skipf("UDP недоступен в окружении: %v", err)
	}
	defer cli.Close()
	if err := cli.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}

	frame, err := sm.Encrypt(1, []byte("ping"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cli.WriteTo(frame, recv.LocalAddr()); err != nil {
		t.Fatal(err)
	}

	fr, err := recv.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if string(fr.Payload) != "ping" {
		t.Fatalf("payload: %q", fr.Payload)
	}
	echo := append([]byte("echo:"), fr.Payload...)
	if _, err := recv.SendTo(fr.Src, fr.Seq, echo, 64); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 65535)
	n, _, err := cli.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	seq, pt, err := sm.Decrypt(buf[:n])
	if err != nil {
		t.Fatalf("эхо не расшифровалось: %v", err)
	}
	if seq != 1 || string(pt) != "echo:ping" {
		t.Fatalf("эхо: seq=%d payload=%q", seq, pt)
	}
}
