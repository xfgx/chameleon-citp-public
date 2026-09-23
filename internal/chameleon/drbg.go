package chameleon

import (
	"crypto/sha512"
	"encoding/binary"
)

// DRBG — детерминированный генератор псевдослучайных чисел на SHA-512
// в счётчикном режиме. Клиент и сервер с одинаковым seed воспроизводят
// байт-в-байт одинаковый поток — это основа "маски" сеанса: обе стороны
// знают, как будет выглядеть трафик, а для ТСПУ это белый шум.
type DRBG struct {
	material []byte // seed || 0x00 || label
	ctr      uint64
	buf      []byte
	pos      int
}

func NewDRBG(seed []byte, label string) *DRBG {
	m := make([]byte, 0, len(seed)+1+len(label))
	m = append(m, seed...)
	m = append(m, 0)
	m = append(m, label...)
	return &DRBG{material: m}
}

func (d *DRBG) refill() {
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], d.ctr)
	d.ctr++
	h := sha512.New()
	h.Write(d.material)
	h.Write(c[:])
	d.buf = h.Sum(nil)
	d.pos = 0
}

// Read заполняет p псевдослучайными байтами. Реализует io.Reader.
func (d *DRBG) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if d.pos >= len(d.buf) {
			d.refill()
		}
		k := copy(p[n:], d.buf[d.pos:])
		d.pos += k
		n += k
	}
	return n, nil
}

func (d *DRBG) Uint64() uint64 {
	var b [8]byte
	_, _ = d.Read(b[:])
	return binary.BigEndian.Uint64(b[:])
}

// Intn возвращает число в диапазоне [0, n). Для масок смещение modulo не важно.
func (d *DRBG) Intn(n int) int {
	if n <= 0 {
		return 0
	}
	return int(d.Uint64() % uint64(n))
}

func (d *DRBG) Bytes(n int) []byte {
	b := make([]byte, n)
	_, _ = d.Read(b)
	return b
}
