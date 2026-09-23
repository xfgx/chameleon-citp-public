package chameleon

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"
)

// CITP (Chameleon Intent Transport Protocol) Object Model & Semantic Delivery Modes
//
// В отличие от классического пакетного VPN, CITP оперирует типизированными объектами
// с контролируемой семантикой доставки (reliable, expiring, latest-only, resumable).

// DeliveryMode определяет семантику доставки объекта через туннель.
type DeliveryMode uint8

const (
	// ModeReliableOrdered — стандартный надёжный упорядоченный поток (как TCP / HTTP payload / Control).
	ModeReliableOrdered DeliveryMode = 0x01

	// ModeReliableUnordered — надёжная доставка без привязки к порядку (параллельные чанки / асинхронные события).
	ModeReliableUnordered DeliveryMode = 0x02

	// ModeExpiring — доставка с дедлайном (если время вышло, объект дропается; отлично для real-time UDP / VoIP / игровых пакетов).
	ModeExpiring DeliveryMode = 0x03

	// ModeLatestOnly — сохраняется/обрабатывается только самый свежий объект для данного Stream/Channel (состояние, телеметрия).
	ModeLatestOnly DeliveryMode = 0x04

	// ModePartialReliable — доставка с ограниченным количеством повторов или допустимостью потерь (видео / аудио кадры).
	ModePartialReliable DeliveryMode = 0x05
)

// ObjectType определяет тип полезной нагрузки CITP объекта.
type ObjectType uint16

const (
	ObjTypeIntentOpen      ObjectType = 0x0001 // Намерение открыть соединение (с DNS binding, policy)
	ObjTypeStreamChunk     ObjectType = 0x0002 // Чанк данных потока
	ObjTypeDatagramBatch   ObjectType = 0x0003 // Пакет датаграмм (сжатый/базовый UDP)
	ObjTypePolicyUpdate    ObjectType = 0x0004 // Обновление правил/политик маршрутизации
	ObjTypeMigrationTicket ObjectType = 0x0005 // Билет миграции потока между нодами/сетями
	ObjTypeResumeStream    ObjectType = 0x0006 // Запрос возобновления потока (с offset reconciliation)
	ObjTypeResumeAck       ObjectType = 0x0007 // Подтверждение возобновления потока
	ObjTypeCloseIntent     ObjectType = 0x0008 // Явное закрытие намерения/потока
)

// CITPObject — универсальный заголовок и тело CITP объекта.
//
// Структура сериализации:
//
//	[8 байт: ObjectID uint64]
//	[8 байт: ParentID uint64] (причинно-следственная связь / causality)
//	[4 байт: StreamID uint32]
//	[2 байт: Type uint16]
//	[1 байт: DeliveryMode uint8]
//	[1 байт: Flags uint8]
//	[8 байт: Offset uint64]   (смещение потока для reliable/resumable)
//	[8 байт: ExpiryUnixMs int64] (дедлайн жизни объекта в мс, 0 = без дедлайна)
//	[8 байт: MonotonicSeq uint64] (номер эпохи / монотонный счетчик)
//	[2 байт: PayloadLen uint16]
//	[PayloadLen байт: Payload]
//	[32 байта: AuthTag HMAC-SHA256] (опционально, если привязано к сессии)
type CITPObject struct {
	ObjectID     uint64
	ParentID     uint64
	StreamID     uint32
	Type         ObjectType
	Mode         DeliveryMode
	Flags        uint8
	Offset       uint64
	ExpiryUnixMs int64
	MonotonicSeq uint64
	Payload      []byte
	AuthTag      []byte
}

const (
	citpHeaderLen     = 8 + 8 + 4 + 2 + 1 + 1 + 8 + 8 + 8 + 2 // 50 байт без payload и authTag
	authTagLen        = 32
	maxCITPPayloadLen = 65535 // жесткое ограничение размера объекта (uint16 max)
)

// Encode сериализует объект CITP в байтовый массив.
func (obj *CITPObject) Encode() []byte {
	if len(obj.Payload) > maxCITPPayloadLen {
		return nil
	}
	totalLen := citpHeaderLen + len(obj.Payload)
	if len(obj.AuthTag) == authTagLen {
		totalLen += authTagLen
	}
	buf := make([]byte, totalLen)

	binary.BigEndian.PutUint64(buf[0:8], obj.ObjectID)
	binary.BigEndian.PutUint64(buf[8:16], obj.ParentID)
	binary.BigEndian.PutUint32(buf[16:20], obj.StreamID)
	binary.BigEndian.PutUint16(buf[20:22], uint16(obj.Type))
	buf[22] = byte(obj.Mode)
	buf[23] = obj.Flags
	binary.BigEndian.PutUint64(buf[24:32], obj.Offset)
	binary.BigEndian.PutUint64(buf[32:40], uint64(obj.ExpiryUnixMs))
	binary.BigEndian.PutUint64(buf[40:48], obj.MonotonicSeq)
	binary.BigEndian.PutUint16(buf[48:50], uint16(len(obj.Payload)))

	copy(buf[citpHeaderLen:citpHeaderLen+len(obj.Payload)], obj.Payload)

	if len(obj.AuthTag) == authTagLen {
		copy(buf[citpHeaderLen+len(obj.Payload):], obj.AuthTag)
	}
	return buf
}

// DecodeCITPObject десериализует объект CITP из байтов.
func DecodeCITPObject(b []byte) (*CITPObject, error) {
	if len(b) < citpHeaderLen {
		return nil, errors.New("citp: object too short")
	}
	pLen := int(binary.BigEndian.Uint16(b[48:50]))
	if pLen > maxCITPPayloadLen {
		return nil, errors.New("citp: payload size exceeds maximum limit")
	}
	if len(b) < citpHeaderLen+pLen {
		return nil, errors.New("citp: payload truncated")
	}
	obj := &CITPObject{
		ObjectID:     binary.BigEndian.Uint64(b[0:8]),
		ParentID:     binary.BigEndian.Uint64(b[8:16]),
		StreamID:     binary.BigEndian.Uint32(b[16:20]),
		Type:         ObjectType(binary.BigEndian.Uint16(b[20:22])),
		Mode:         DeliveryMode(b[22]),
		Flags:        b[23],
		Offset:       binary.BigEndian.Uint64(b[24:32]),
		ExpiryUnixMs: int64(binary.BigEndian.Uint64(b[32:40])),
		MonotonicSeq: binary.BigEndian.Uint64(b[40:48]),
	}
	obj.Payload = append([]byte(nil), b[citpHeaderLen:citpHeaderLen+pLen]...)

	rem := len(b) - (citpHeaderLen + pLen)
	if rem != 0 && rem != authTagLen {
		return nil, errors.New("citp: invalid trailing data")
	}
	if rem == authTagLen {
		obj.AuthTag = append([]byte(nil), b[citpHeaderLen+pLen:]...)
	}
	return obj, nil
}

// IsExpired проверяет, истёк ли срок годности объекта.
func (obj *CITPObject) IsExpired(nowMs int64) bool {
	if obj.ExpiryUnixMs <= 0 {
		return false
	}
	return nowMs > obj.ExpiryUnixMs
}

// Sign подписывает объект HMAC-SHA256 ключом сессии.
func (obj *CITPObject) Sign(sessionKey []byte) {
	tag := hmacSHA256(sessionKey, obj.signData())
	obj.AuthTag = tag
}

// Verify проверяет HMAC-SHA256 тег объекта.
func (obj *CITPObject) Verify(sessionKey []byte) bool {
	if len(obj.AuthTag) != authTagLen {
		return false
	}
	expected := hmacSHA256(sessionKey, obj.signData())
	return hmac.Equal(obj.AuthTag, expected)
}

func (obj *CITPObject) signData() []byte {
	buf := make([]byte, citpHeaderLen+len(obj.Payload))
	binary.BigEndian.PutUint64(buf[0:8], obj.ObjectID)
	binary.BigEndian.PutUint64(buf[8:16], obj.ParentID)
	binary.BigEndian.PutUint32(buf[16:20], obj.StreamID)
	binary.BigEndian.PutUint16(buf[20:22], uint16(obj.Type))
	buf[22] = byte(obj.Mode)
	buf[23] = obj.Flags
	binary.BigEndian.PutUint64(buf[24:32], obj.Offset)
	binary.BigEndian.PutUint64(buf[32:40], uint64(obj.ExpiryUnixMs))
	binary.BigEndian.PutUint64(buf[40:48], obj.MonotonicSeq)
	binary.BigEndian.PutUint16(buf[48:50], uint16(len(obj.Payload)))
	copy(buf[citpHeaderLen:], obj.Payload)
	return buf
}
