package chameleon

// continuity.go — CST (Causal State Transport): криптография непрерывности.
//
// Восстановление логического потока НЕ подписывается seed старой физической
// сессии (грех старого MigrationTicket). При KnowledgeOpen клиент генерирует
// случайный FlowSecret и ОДИН раз передаёт его ноде внутри AEAD-канала (в
// тикеты/манифесты он не попадает никогда). Из FlowSecret выводится
// continuity key (CK), криптографически привязанный ко всем идентичностям:
//
//   CK = HKDF(FlowSecret, info="cst-continuity-v1" || ver || FlowID ||
//             clientPub || nodePub || SHA256(target))
//
// Дельты и ACK подписываются ключами, привязанными к направлению и
// ПОКОЛЕНИЮ (generation): дельта старого поколения не проходит ни по явной
// проверке gen, ни по HMAC (ключ другого поколения). Attach-манифест
// привязан к НОВОЙ физической сессии: в MAC входит seed текущего сеанса —
// replay манифеста старой сессии не сходится по MAC. Свежий nonce клиента
// в манифесте исключает переиспользование nonce.
//
// Примитивы — только существующие проверенные: HKDF/HMAC-SHA256.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
)

// CSTVersion — версия проводного протокола CST.
const CSTVersion uint16 = 1

// Направления потока (от лица клиента).
const (
	CSTDirC2S uint8 = 0 // клиент -> нода -> цель
	CSTDirS2C uint8 = 1 // цель -> нода -> клиент
)

// Режимы потока.
const (
	CSTModeTCP uint8 = 0 // строго последовательный байт-поток
	CSTModeUDP uint8 = 1 // независимые датаграммы
)

// Флаги дельты.
const (
	CSTFlagFIN      uint8 = 1 << 0 // отправитель закрыл направление
	CSTFlagDatagram uint8 = 1 << 1 // payload — одна датаграмма (UDP-режим)
)

// FlowID — стабильный случайный идентификатор логического потока.
// НЕ совпадает со StreamID мультиплексора и переживает смену Mux/cell.
type FlowID [16]byte

// NewFlowID генерирует криптографически случайный FlowID.
func NewFlowID() FlowID {
	var id FlowID
	_, _ = rand.Read(id[:])
	return id
}

// FlowContinuity — continuity-ключ потока и производные ключи.
type FlowContinuity struct {
	ID FlowID
	ck []byte
}

// DeriveContinuity выводит continuity key. target — каноническая форма
// цели, одинаковая на обеих сторонах. clientPub/nodePub — 32-байтные
// публичные ключи X25519.
func DeriveContinuity(flowSecret, clientPub, nodePub []byte, id FlowID, target string) *FlowContinuity {
	tHash := sha256.Sum256([]byte(target))
	info := make([]byte, 0, 20+2+16+32+32+32)
	info = append(info, "cst-continuity-v1"...)
	info = binary.BigEndian.AppendUint16(info, CSTVersion)
	info = append(info, id[:]...)
	info = append(info, clientPub...)
	info = append(info, nodePub...)
	info = append(info, tHash[:]...)
	ck, _ := hkdfKey(flowSecret, nil, string(info), 32)
	return &FlowContinuity{ID: id, ck: ck}
}

// key — производный ключ HKDF(CK, label || dir || gen). dir=0xff — ключ без
// направления (attach/detach/close/snapshot).
func (fc *FlowContinuity) key(label string, dir uint8, gen uint32) []byte {
	if fc == nil {
		// Нулевой ключ: Encode на nil-fc даёт кадр корректной длины и не
		// паникует. Тег при этом НЕ авторитетен, поэтому все Verify*-методы
		// на nil-fc возвращают false (fail closed).
		return make([]byte, 32)
	}
	info := make([]byte, 0, len(label)+5)
	info = append(info, label...)
	info = append(info, dir)
	info = binary.BigEndian.AppendUint32(info, gen)
	k, _ := hkdfKey(fc.ck, nil, string(info), 32)
	return k
}

// DeltaKey — ключ подписи дельт направления dir поколения gen.
func (fc *FlowContinuity) DeltaKey(dir uint8, gen uint32) []byte {
	return fc.key("cst-delta-v1", dir, gen)
}

// AckKey — ключ подписи knowledge-ACK направления dir поколения gen.
func (fc *FlowContinuity) AckKey(dir uint8, gen uint32) []byte {
	return fc.key("cst-ack-v1", dir, gen)
}

// AttachKey — ключ MAC манифеста присоединения (свежесть — от seed новой
// сессии внутри подписываемых данных).
func (fc *FlowContinuity) AttachKey() []byte {
	return fc.key("cst-attach-v1", 0xff, 0)
}

// DetachKey — ключ тега штатного отсоединения поколения gen.
func (fc *FlowContinuity) DetachKey(gen uint32) []byte {
	return fc.key("cst-detach-v1", 0xff, gen)
}

// CloseKey — ключ тега закрытия потока.
func (fc *FlowContinuity) CloseKey() []byte {
	return fc.key("cst-close-v1", 0xff, 0)
}

// SnapshotKey — ключ MAC snapshot/compaction поколения gen.
func (fc *FlowContinuity) SnapshotKey(gen uint32) []byte {
	return fc.key("cst-snapshot-v1", 0xff, gen)
}

// OpenKey — ключ MAC кадра KnowledgeOpen (доказывает владение FlowSecret,
// привязывает FlowID). CK выводится обеими сторонами ПОСЛЕ приёма open.
func OpenKey(flowSecret []byte, id FlowID) []byte {
	info := append([]byte("cst-open-v1"), id[:]...)
	k, _ := hkdfKey(flowSecret, nil, string(info), 32)
	return k
}

// Zeroize затирает continuity key (best-effort для Go). Идемпотентно.
func (fc *FlowContinuity) Zeroize() {
	if fc == nil {
		return
	}
	for i := range fc.ck {
		fc.ck[i] = 0
	}
}

// ZeroizeBytes затирает секретный буфер (FlowSecret и т.п.).
func ZeroizeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
