package chameleon

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"
)

func fixedPhantomEngine() *PhantomEngine {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	return NewPhantomEngine(secret)
}

func fixedChunk() [12]byte {
	var c [12]byte
	for i := range c {
		c[i] = byte(0xA0 + i)
	}
	return c
}

func TestZPL4RoundTrip(t *testing.T) {
	pe := fixedPhantomEngine()
	dst := net.IPv4(203, 0, 113, 9) // параметр кодирования; на провод ничего не уходит
	for i := 0; i < 4096; i++ {
		var chunk [12]byte
		binary.BigEndian.PutUint64(chunk[0:8], uint64(i+1000))
		binary.BigEndian.PutUint32(chunk[8:12], uint32(i*7))
		hdr := pe.EncodeZPL4(chunk, net.IPv4(192, 0, 2, 1), dst, uint16(53+i%1000))
		if hdr.Payload != nil {
			t.Fatal("ZPL4: L7 payload должен отсутствовать")
		}
		res, ok := pe.DecodeZPL4(hdr, uint64(i+1))
		if !ok {
			t.Fatalf("пакет %d: подлинность не подтверждена", i)
		}
		if res != chunk {
			t.Fatalf("пакет %d: восстановленный chunk не совпал", i)
		}
	}
}

func TestZPL4WrongSequence(t *testing.T) {
	pe := fixedPhantomEngine()
	hdr := pe.EncodeZPL4(fixedChunk(), net.IPv4(192, 0, 2, 1), net.IPv4(203, 0, 113, 9), 443)
	if _, ok := pe.DecodeZPL4(hdr, 2); ok {
		t.Fatal("декодирование с чужим seqNum должно отклоняться")
	}
}

func TestZPL4TamperDetection(t *testing.T) {
	pe := fixedPhantomEngine()
	orig := pe.EncodeZPL4(fixedChunk(), net.IPv4(192, 0, 2, 1), net.IPv4(203, 0, 113, 9), 443)

	mutants := []PhantomHeader{orig, orig, orig, orig}
	mutants[0].Seq ^= 1
	mutants[1].Ack ^= 0x80000000
	mutants[2].TSval ^= 0x01010101
	mutants[3].IPv4ID ^= 0xFFFF
	for i, m := range mutants {
		if _, ok := pe.DecodeZPL4(m, 1); ok {
			t.Fatalf("мутант %d принят как подлинный", i)
		}
	}
}

func TestZPL4KeySeparation(t *testing.T) {
	a := fixedPhantomEngine()
	other := make([]byte, 32)
	for i := range other {
		other[i] = byte(0xFF - i)
	}
	b := NewPhantomEngine(other)
	hdr := a.EncodeZPL4(fixedChunk(), net.IPv4(192, 0, 2, 1), net.IPv4(203, 0, 113, 9), 443)
	if _, ok := b.DecodeZPL4(hdr, 1); ok {
		t.Fatal("чужой ключ не должен декодировать заголовок")
	}
}

func TestZPL4SrcPortRange(t *testing.T) {
	pe := fixedPhantomEngine()
	for i := 0; i < 1000; i++ {
		hdr := pe.EncodeZPL4(fixedChunk(), net.IPv4(192, 0, 2, 1), net.IPv4(203, 0, 113, 9), 443)
		if hdr.SrcPort < 40000 || hdr.SrcPort > 59999 {
			t.Fatalf("SrcPort %d вне диапазона 40000-59999", hdr.SrcPort)
		}
	}
}

func TestShannonEntropy(t *testing.T) {
	if e := CalculateShannonEntropy(nil); e != 0 {
		t.Fatalf("пустой ввод: %v", e)
	}
	if e := CalculateShannonEntropy(make([]byte, 1<<20)); e != 0 {
		t.Fatalf("нули: %v", e)
	}
	// идеальная равномерность: каждый байт ровно 4096 раз → 8.0 бит/байт
	uniform := make([]byte, 0, 256*4096)
	for i := 0; i < 4096; i++ {
		for b := 0; b < 256; b++ {
			uniform = append(uniform, byte(b))
		}
	}
	if e := CalculateShannonEntropy(uniform); e != 8.0 {
		t.Fatalf("равномерный поток: %v != 8.0", e)
	}
	rnd := make([]byte, 1<<20)
	if _, err := rand.Read(rnd); err != nil {
		t.Fatal(err)
	}
	if e := CalculateShannonEntropy(rnd); e < 7.9 {
		t.Fatalf("энтропия случайного потока слишком низкая: %.4f", e)
	}
}

func TestZPL4HeaderEntropy(t *testing.T) {
	pe := fixedPhantomEngine()
	var buf bytes.Buffer
	for i := 0; i < 100000; i++ {
		var chunk [12]byte
		binary.BigEndian.PutUint64(chunk[0:8], uint64(i+1000))
		binary.BigEndian.PutUint32(chunk[8:12], uint32(i*7))
		hdr := pe.EncodeZPL4(chunk, net.IPv4(192, 0, 2, 1), GenerateRandomIP(uint64(i)), uint16(53+i%1000))
		var w [12]byte
		binary.BigEndian.PutUint32(w[0:4], hdr.Seq)
		binary.BigEndian.PutUint32(w[4:8], hdr.Ack)
		binary.BigEndian.PutUint32(w[8:12], hdr.TSval)
		buf.Write(w[:])
	}
	if e := CalculateShannonEntropy(buf.Bytes()); e < 7.9 {
		t.Fatalf("энтропия заголовков %.4f < 7.9", e)
	}
}

func TestGenerateRandomIPPublic(t *testing.T) {
	seen := make(map[string]struct{})
	for i := uint64(0); i < 100000; i++ {
		ip := GenerateRandomIP(i)
		b := ip.To4()
		if b == nil {
			t.Fatalf("не IPv4: %v", ip)
		}
		if !isPublicIPv4([4]byte{b[0], b[1], b[2], b[3]}) {
			t.Fatalf("зарезервированный адрес %v (seed %d)", ip, i)
		}
		seen[ip.String()] = struct{}{}
	}
	if len(seen) < 90000 {
		t.Fatalf("слишком мало уникальных IP: %d из 100000", len(seen))
	}
}

func BenchmarkZPL4Encode(b *testing.B) {
	pe := fixedPhantomEngine()
	chunk := fixedChunk()
	dst := net.IPv4(203, 0, 113, 9)
	src := net.IPv4(192, 0, 2, 1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pe.EncodeZPL4(chunk, src, dst, 443)
	}
}

func BenchmarkZPL4Decode(b *testing.B) {
	pe := fixedPhantomEngine()
	chunk := fixedChunk()
	hdr := pe.EncodeZPL4(chunk, net.IPv4(192, 0, 2, 1), net.IPv4(203, 0, 113, 9), 443)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pe.DecodeZPL4(hdr, 1)
	}
}
