package chameleon

import (
	"crypto/hmac"
	"encoding/binary"
	"math"
	"net"
	"sync/atomic"
	"time"
)

// phantom.go — CITP v3.0: CPI-Scatter и ZPL4.
//
// CPI-Scatter (Cryptographic Phantom IP Scattering) — распределение потока по
// произвольным глобальным IP-адресам назначения с криптографической меткой в
// заголовках L4, по которой сопряжённая нода узнаёт «свой» пакет за O(1).
//
// ZPL4 (Zero-Payload L4 Steganography) — перенос 12 байт данных внутри полей
// TCP-заголовка (Seq, Ack, TSval) при нулевой полезной нагрузке (Len=0).
// DPI не может заблокировать «пустой» TCP ACK, не ломая весь TCP/IP.
//
// ВАЖНО (отличие от эталонного прототипа): декодер восстанавливает данные
// ИСКЛЮЧИТЕЛЬНО из проводных полей заголовка — XOR-маска вычисляется только из
// номера пакета (он известен обеим сторонам по синхронному счётчику), а IPv4ID
// несёт усечённый тег подлинности над восстановленным чанком. Прототип читал
// поле HeaderData, которого у реального приёмника нет, — на проводе такая
// схема не работала бы.
//
// Схема размещения 12 байт чанка:
//
//	Seq    = chunk[0:4]  XOR mask[0:4]
//	Ack    = chunk[4:8]  XOR mask[4:8]
//	TSval  = chunk[8:12] XOR mask[8:12]
//	mask   = HMAC-SHA256(hmacKey, "zpl4-mask"  || seqNum)
//	IPv4ID = HMAC-SHA256(hmacKey, "zpl4-check" || seqNum || chunk)[12:14]
//
// Приёмник знает seqNum, вычисляет mask, восстанавливает chunk XOR-ом и
// сверяет IPv4ID. Посторонний без hmacKey видит криптографический белый шум.

// PhantomHeader — значения полей IP/TCP-заголовка фантомного пакета.
// Payload всегда nil: ZPL4 не несёт L7-данных.
type PhantomHeader struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
	Seq     uint32
	Ack     uint32
	Window  uint16
	IPv4ID  uint16
	TSval   uint32
	TSecr   uint32
	Payload []byte
}

// PhantomEngine кодирует и декодирует ZPL4-заголовки с привязкой к сессии.
type PhantomEngine struct {
	hmacKey       []byte
	packetCounter uint64
}

// NewPhantomEngine выводит ключ маркировки из сессионного секрета.
// Деривация совместима с эталонным прототипом CITP v3.0.
func NewPhantomEngine(secret []byte) *PhantomEngine {
	return &PhantomEngine{
		hmacKey: hmacSHA256(secret, []byte("CITP-v3-Phantom-Entanglement-Key")),
	}
}

// zpl4Mask вычисляет XOR-маску (12 байт используются) для номера пакета.
func (pe *PhantomEngine) zpl4Mask(seqNum uint64) []byte {
	var seqBuf [8]byte
	binary.BigEndian.PutUint64(seqBuf[:], seqNum)
	return hmacSHA256(pe.hmacKey, append([]byte("zpl4-mask"), seqBuf[:]...))
}

// zpl4CheckTag вычисляет тег подлинности; байты [12:14] уходят в IPv4ID.
func (pe *PhantomEngine) zpl4CheckTag(seqNum uint64, chunk [12]byte) []byte {
	var seqBuf [8]byte
	binary.BigEndian.PutUint64(seqBuf[:], seqNum)
	msg := append([]byte("zpl4-check"), seqBuf[:]...)
	msg = append(msg, chunk[:]...)
	return hmacSHA256(pe.hmacKey, msg)
}

// EncodeZPL4 кодирует 12 байт в поля TCP-заголовка (Seq, Ack, TSval, IPv4ID).
func (pe *PhantomEngine) EncodeZPL4(chunk [12]byte, srcIP, dstIP net.IP, dstPort uint16) PhantomHeader {
	seqNum := atomic.AddUint64(&pe.packetCounter, 1)
	mask := pe.zpl4Mask(seqNum)
	tag := pe.zpl4CheckTag(seqNum, chunk)

	seq := binary.BigEndian.Uint32(chunk[0:4]) ^ binary.BigEndian.Uint32(mask[0:4])
	ack := binary.BigEndian.Uint32(chunk[4:8]) ^ binary.BigEndian.Uint32(mask[4:8])
	tsval := binary.BigEndian.Uint32(chunk[8:12]) ^ binary.BigEndian.Uint32(mask[8:12])

	return PhantomHeader{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: uint16(40000 + (seqNum % 20000)),
		DstPort: dstPort,
		Seq:     seq,
		Ack:     ack,
		Window:  8192,
		IPv4ID:  binary.BigEndian.Uint16(tag[12:14]),
		TSval:   tsval,
		TSecr:   uint32(time.Now().Unix()),
		Payload: nil, // ZPL4: L7-полезная нагрузка отсутствует
	}
}

// DecodeZPL4 восстанавливает 12 байт из проводных полей и проверяет IPv4ID.
// ok=false: пакет чужой, повреждён или seqNum не совпал.
func (pe *PhantomEngine) DecodeZPL4(hdr PhantomHeader, seqNum uint64) (chunk [12]byte, ok bool) {
	mask := pe.zpl4Mask(seqNum)

	binary.BigEndian.PutUint32(chunk[0:4], hdr.Seq^binary.BigEndian.Uint32(mask[0:4]))
	binary.BigEndian.PutUint32(chunk[4:8], hdr.Ack^binary.BigEndian.Uint32(mask[4:8]))
	binary.BigEndian.PutUint32(chunk[8:12], hdr.TSval^binary.BigEndian.Uint32(mask[8:12]))

	tag := pe.zpl4CheckTag(seqNum, chunk)
	got := []byte{byte(hdr.IPv4ID >> 8), byte(hdr.IPv4ID)}
	if !hmac.Equal(tag[12:14], got) {
		return chunk, false
	}
	return chunk, true
}

// CalculateShannonEntropy — энтропия Шеннона потока байт (бит/байт).
// Идеальный криптографический белый шум стремится к 8.0.
func CalculateShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	var entropy float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / float64(len(data))
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// GenerateRandomIP — детерминированный генератор публичных IPv4 для CPI-Scatter
// (LCG Numerical Recipes). Неподходящие адреса отбрасываются повторной итерацией,
// а не «прижимаются» к фиксированному октету — распределение не искажается.
func GenerateRandomIP(seed uint64) net.IP {
	x := uint32(seed)
	for {
		x = x*1664525 + 1013904223
		b := [4]byte{byte(x >> 24), byte(x >> 16), byte(x >> 8), byte(x)}
		if isPublicIPv4(b) {
			return net.IPv4(b[0], b[1], b[2], b[3])
		}
	}
}

// isPublicIPv4 отсекает маршрутизационные болота (RFC 6890): private, loopback,
// link-local, CGNAT, multicast/reserved, benchmarking и документационные сети.
func isPublicIPv4(b [4]byte) bool {
	switch {
	case b[0] == 0 || b[0] == 10 || b[0] == 127 || b[0] >= 224:
		return false
	case b[0] == 100 && b[1] >= 64 && b[1] <= 127: // 100.64.0.0/10 CGNAT
		return false
	case b[0] == 169 && b[1] == 254: // link-local
		return false
	case b[0] == 172 && b[1] >= 16 && b[1] <= 31: // 172.16.0.0/12
		return false
	case b[0] == 192 && b[1] == 168: // 192.168.0.0/16
		return false
	case b[0] == 192 && b[1] == 0 && (b[2] == 0 || b[2] == 2): // 192.0.0.0/24, TEST-NET-1
		return false
	case b[0] == 198 && (b[1] == 18 || b[1] == 19): // 198.18.0.0/15 benchmark
		return false
	case b[0] == 198 && b[1] == 51 && b[2] == 100: // TEST-NET-2
		return false
	case b[0] == 203 && b[1] == 0 && b[2] == 113: // TEST-NET-3
		return false
	}
	return true
}
