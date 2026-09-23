package chaossync

// cst.go — Continuity Session Ticket: непрерывность логической идентичности
// поверх мутирующего векторного поля.
//
// Физический слой мутирует каждые T секунд (новое f_k, новый аттрактор,
// reseed состояния). Логическая сессия при этом не рвётся: её носителем
// служит цепочка sid_m = SHA256(master ‖ "chaossync-cst-v1" ‖ m) — обе
// стороны вычисляют её локально для любой эпохи. Значением sid_m
// подписываются кадры битового уровня (FrameTag): получатель кадра эпохи m
// доказывает знание мастер-ключа и непрерывность сессии, не раскрывая
// ни ключ, ни счётчики на проводе (тег идёт в модуляционном домене,
// а не в UDP-датаграмме).
//
// Замечание о модели угроз: компрометация sid_m одной эпохи не раскрывает
// sid других эпох (независимый KDF на эпоху), а replay кадра чужой эпохи
// отбрасывается проверкой тега.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

// FrameTagLen — длина тега кадра в байтах (16 бит × 8 = 2 байта в кадре;
// достаточно для демо-транспорта: вероятность навязанного кадра 2^-16,
// каждый неверный тег считается и логируется).
const FrameTagLen = 2

// FrameTag — HMAC-SHA256(sid_m, epoch ‖ frameSeq ‖ payload), усечённый до
// FrameTagLen байт. Детерминирован, проверяется локально.
func FrameTag(master []byte, epoch, frameSeq uint64, payload []byte) [FrameTagLen]byte {
	sid := SidForEpoch(master, epoch)
	m := hmac.New(sha256.New, sid)
	var b [16]byte
	binary.BigEndian.PutUint64(b[0:8], epoch)
	binary.BigEndian.PutUint64(b[8:16], frameSeq)
	m.Write(b[:])
	m.Write(payload)
	var tag [FrameTagLen]byte
	copy(tag[:], m.Sum(nil))
	return tag
}

// CheckFrameTag — сверка тега (constant-time относительно payload).
func CheckFrameTag(master []byte, epoch, frameSeq uint64, payload []byte, tag []byte) bool {
	if len(tag) != FrameTagLen {
		return false
	}
	want := FrameTag(master, epoch, frameSeq, payload)
	return hmac.Equal(want[:], tag)
}
