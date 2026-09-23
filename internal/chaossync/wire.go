package chaossync

// wire.go — проводной кодек. По UDP ходит ТОЛЬКО квантованный скаляр:
// никаких заголовков, границ сообщений, sequence-полей и структуры пакета.
// Датаграмма = Batch × uint16 (big-endian) подряд идущих сэмплов.

import "encoding/binary"

// Quantize16 — квантование x ∈ [0,1) в 16 бит: старшие разряды дробной
// части Q16.48. Значения вне [0,1) насыщаются (канал/коррекция могут дать
// микровыбросы; обе стороны насыщают одинаково).
func Quantize16(x Fxp) uint16 {
	r := int64(x)
	if r < 0 {
		r = 0
	}
	if r >= oneRaw {
		r = oneRaw - 1
	}
	return uint16(uint64(r) >> 32)
}

// Dequantize16 — восстановление в середину кванта (несмещённая оценка).
func Dequantize16(q uint16) Fxp {
	return Fxp((int64(q) << 32) | (1 << 31))
}

// EncodeSamples упаковывает квантованные сэмплы в датаграмму (2 байта на
// сэмпл, big-endian, без служебных полей).
func EncodeSamples(dst []byte, q []uint16) int {
	for i, v := range q {
		binary.BigEndian.PutUint16(dst[i*2:], v)
	}
	return len(q) * 2
}

// DecodeSamples распаковывает датаграмму. Нечётная длина — fail-closed:
// лишний байт отбрасывается, целостность не выдумывается.
func DecodeSamples(dat []byte, q []uint16) int {
	n := len(dat) / 2
	if n > len(q) {
		n = len(q)
	}
	for i := 0; i < n; i++ {
		q[i] = binary.BigEndian.Uint16(dat[i*2:])
	}
	return n
}
