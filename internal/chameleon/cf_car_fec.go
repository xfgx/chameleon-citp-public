package chameleon

// cf_car_fec.go — Этап A2: кадрирование и помехоустойчивость CAR-канала.
//
// Вердикт-канал шумный (тайминги ТСПУ плавают, единичные вердикты инвертируются
// или выпадают), поэтому биты кадрируются:
//
//   [ SYNC:8 | LEN:8 | PAYLOAD:LEN*8 | CRC16:16 ] — каждый бит повторяется rep раз
//
//   - SYNC (0xAC) — маркер начала кадра;
//   - LEN — длина payload в байтах (CAR несёт только короткие команды,
//     максимум CARMaxPayload);
//   - CRC-16-CCITT поверх SYNC|LEN|PAYLOAD ловит повреждения, которые
//     repetition-код не исправил;
//   - repetition (по умолчанию 3) с мажоритарным декодированием гасит
//     одиночные инверсии/выпадения вердиктов.
//
// Читатель сначала восстанавливает заголовок (SYNC+LEN), затем дочитывает
// ровно столько окон, сколько занимает payload+CRC. При несовпадении SYNC/CRC
// кадр отбрасывается — вызывающая сторона читает окна заново (состояние на
// ноде статично, повторное чтение даёт независимые шумовые выборки).

import (
	"encoding/binary"
	"errors"
)

const (
	// CARFrameSyncByte — маркер начала кадра.
	CARFrameSyncByte = 0xAC

	// CARFrameRep — фактор повторения по умолчанию (мажоритарно из 3).
	CARFrameRep = 3

	// CARMaxPayload — потолок payload одного CAR-кадра (control-plane only).
	CARMaxPayload = 255

	carFrameHeaderBits = 16 // SYNC + LEN
	carFrameCRCBits    = 16 // CRC-16
)

// ErrCARFrameCorrupt — кадр не прошёл проверку SYNC/LEN/CRC (шум канала
// превысил исправляющую способность repetition-кода).
var ErrCARFrameCorrupt = errors.New("car: frame failed sync/len/crc check")

// CARFrameWindows — сколько окон кодовой книги занимает на проводе кадр с
// payload до maxPayload байт при факторе повторения rep.
func CARFrameWindows(maxPayload, rep int) int {
	if rep <= 0 {
		rep = CARFrameRep
	}
	if maxPayload < 0 {
		maxPayload = 0
	}
	return (carFrameHeaderBits + 8*maxPayload + carFrameCRCBits) * rep
}

// EncodeCARFrame кодирует сообщение в поток бит-вердиктов (каждый бит
// повторяется rep раз подряд). Возвращает nil, если сообщение длиннее
// CARMaxPayload.
func EncodeCARFrame(msg []byte, rep int) []uint8 {
	if rep <= 0 {
		rep = CARFrameRep
	}
	if len(msg) > CARMaxPayload {
		return nil
	}
	body := make([]byte, 0, 2+len(msg)+2)
	body = append(body, CARFrameSyncByte, byte(len(msg)))
	body = append(body, msg...)
	var crcb [2]byte
	binary.BigEndian.PutUint16(crcb[:], crc16CCITT(body))
	body = append(body, crcb[:]...)

	logical := bytesToCARBits(body)
	out := make([]uint8, 0, len(logical)*rep)
	for _, b := range logical {
		for j := 0; j < rep; j++ {
			out = append(out, b)
		}
	}
	return out
}

// DecodeCARFrameHeader восстанавливает длину payload из первых
// carFrameHeaderBits*rep бит кадра. Нужна читателю для двухфазного чтения.
func DecodeCARFrameHeader(bits []uint8, rep int) (int, error) {
	if rep <= 0 {
		rep = CARFrameRep
	}
	if len(bits) < carFrameHeaderBits*rep {
		return 0, ErrCARFrameCorrupt
	}
	hb := carBitsToBytes(carMajority(bits[:carFrameHeaderBits*rep], rep))
	if hb[0] != CARFrameSyncByte {
		return 0, ErrCARFrameCorrupt
	}
	return int(hb[1]), nil
}

// DecodeCARFrame восстанавливает сообщение из потока бит-вердиктов:
// мажоритарное сжатие repetition-групп, проверка SYNC и CRC-16.
func DecodeCARFrame(bits []uint8, rep int) ([]byte, error) {
	if rep <= 0 {
		rep = CARFrameRep
	}
	logical := carMajority(bits, rep)
	if len(logical) < carFrameHeaderBits+carFrameCRCBits {
		return nil, ErrCARFrameCorrupt
	}
	hdr := carBitsToBytes(logical[:carFrameHeaderBits])
	if hdr[0] != CARFrameSyncByte {
		return nil, ErrCARFrameCorrupt
	}
	plen := int(hdr[1])
	need := carFrameHeaderBits + 8*plen + carFrameCRCBits
	if len(logical) < need {
		return nil, ErrCARFrameCorrupt
	}
	body := carBitsToBytes(logical[:need])
	payload := body[2 : len(body)-2]
	want := binary.BigEndian.Uint16(body[len(body)-2:])
	if crc16CCITT(body[:len(body)-2]) != want {
		return nil, ErrCARFrameCorrupt
	}
	out := make([]byte, len(payload))
	copy(out, payload)
	return out, nil
}

// carMajority сжимает каждую группу из rep бит в один бит мажоритарно.
// Хвост, не делящийся на rep, отбрасывается.
func carMajority(bits []uint8, rep int) []uint8 {
	if rep <= 1 {
		out := make([]uint8, len(bits))
		copy(out, bits)
		return out
	}
	n := len(bits) / rep
	out := make([]uint8, n)
	for i := 0; i < n; i++ {
		s := 0
		for j := 0; j < rep; j++ {
			if bits[i*rep+j] != 0 {
				s++
			}
		}
		if s*2 > rep {
			out[i] = 1
		}
	}
	return out
}

// bytesToCARBits раскладывает байты в биты, старшим битом вперёд.
func bytesToCARBits(data []byte) []uint8 {
	out := make([]uint8, 0, len(data)*8)
	for _, b := range data {
		for i := 7; i >= 0; i-- {
			out = append(out, uint8(b>>i)&1)
		}
	}
	return out
}

// carBitsToBytes собирает биты обратно в байты (длина усекается до кратной 8).
func carBitsToBytes(bits []uint8) []byte {
	out := make([]byte, len(bits)/8)
	for i := range out {
		var v byte
		for j := 0; j < 8; j++ {
			v = v<<1 | (bits[i*8+j] & 1)
		}
		out[i] = v
	}
	return out
}

// crc16CCITT — CRC-16-CCITT (poly 0x1021, init 0xFFFF), без таблиц.
func crc16CCITT(data []byte) uint16 {
	crc := uint16(0xFFFF)
	for _, b := range data {
		crc ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}
