package chameleon

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"
)

// DeriveStreamSecret детерминированно вычисляет криптографический StreamSecret
// из сессионного сида узла, StreamID и номера эпохи/транскрипта (FIND-07).
func DeriveStreamSecret(sessionSeed []byte, streamID uint32, epoch uint64) [32]byte {
	var info [12]byte
	binary.BigEndian.PutUint32(info[0:4], streamID)
	binary.BigEndian.PutUint64(info[4:12], epoch)

	r := hkdf.New(sha256.New, sessionSeed, nil, append([]byte("CITP-Stream-Secret-v1:"), info[:]...))
	var out [32]byte
	_, _ = io.ReadFull(r, out[:])
	return out
}

// MigrationTicket позволяет перенести логический поток (Stream) с одной ноды на другую,
// либо переподключить сессию без потери TCP-соединения на сервере.
//
// Структура тикета:
//
//	[8 байт: TicketID uint64]
//	[4 байт: StreamID uint32]
//	[8 байт: SendOffset uint64]    (сколько байт клиент отправил)
//	[8 байт: RecvOffset uint64]    (сколько байт клиент подтвердил получение)
//	[8 байт: ExpiryUnixMs int64]   (дедлайн действия тикета)
//	[32 байт: StreamSecret]        (криптографический токен владения потоком)
//	[32 байт: HMAC-SHA256 Sig]     (подпись сервера или сессии)
type MigrationTicket struct {
	TicketID     uint64
	StreamID     uint32
	SendOffset   uint64
	RecvOffset   uint64
	ExpiryUnixMs int64
	StreamSecret [32]byte
	Sig          []byte
}

const (
	migrationTicketBodyLen = 8 + 4 + 8 + 8 + 8 + 32
	migrationTicketSigLen  = 32
	migrationTicketFullLen = migrationTicketBodyLen + migrationTicketSigLen
)

// NewMigrationTicket создает тикет миграции/восстановления для потока.
func NewMigrationTicket(streamID uint32, sendOff, recvOff uint64, ttl time.Duration, streamSecret [32]byte) *MigrationTicket {
	var tid uint64
	var b [8]byte
	_, _ = io.ReadFull(rand.Reader, b[:])
	tid = binary.BigEndian.Uint64(b[:])

	return &MigrationTicket{
		TicketID:     tid,
		StreamID:     streamID,
		SendOffset:   sendOff,
		RecvOffset:   recvOff,
		ExpiryUnixMs: time.Now().Add(ttl).UnixMilli(),
		StreamSecret: streamSecret,
	}
}

// Encode кодирует MigrationTicket в байты.
func (t *MigrationTicket) Encode() []byte {
	buf := make([]byte, migrationTicketFullLen)
	binary.BigEndian.PutUint64(buf[0:8], t.TicketID)
	binary.BigEndian.PutUint32(buf[8:12], t.StreamID)
	binary.BigEndian.PutUint64(buf[12:20], t.SendOffset)
	binary.BigEndian.PutUint64(buf[20:28], t.RecvOffset)
	binary.BigEndian.PutUint64(buf[28:36], uint64(t.ExpiryUnixMs))
	copy(buf[36:68], t.StreamSecret[:])
	if len(t.Sig) == migrationTicketSigLen {
		copy(buf[68:100], t.Sig)
	}
	return buf
}

// DecodeMigrationTicket декодирует MigrationTicket из байт.
func DecodeMigrationTicket(b []byte) (*MigrationTicket, error) {
	if len(b) != migrationTicketFullLen {
		return nil, errors.New("migration ticket: invalid length")
	}
	t := &MigrationTicket{
		TicketID:     binary.BigEndian.Uint64(b[0:8]),
		StreamID:     binary.BigEndian.Uint32(b[8:12]),
		SendOffset:   binary.BigEndian.Uint64(b[12:20]),
		RecvOffset:   binary.BigEndian.Uint64(b[20:28]),
		ExpiryUnixMs: int64(binary.BigEndian.Uint64(b[28:36])),
		Sig:          append([]byte(nil), b[68:100]...),
	}
	copy(t.StreamSecret[:], b[36:68])
	return t, nil
}

// Sign подписывает тикет ключом сессии / мастер-ключом ноды.
func (t *MigrationTicket) Sign(key []byte) {
	t.Sig = hmacSHA256(key, t.signData())
}

// Verify проверяет валидность тикета.
func (t *MigrationTicket) Verify(key []byte, nowMs int64) error {
	if t.ExpiryUnixMs > 0 && nowMs > t.ExpiryUnixMs {
		return fmt.Errorf("migration ticket expired")
	}
	if len(t.Sig) != migrationTicketSigLen {
		return errors.New("migration ticket missing signature")
	}
	expected := hmacSHA256(key, t.signData())
	if !hmac.Equal(t.Sig, expected) {
		return errors.New("migration ticket signature mismatch")
	}
	return nil
}

func (t *MigrationTicket) signData() []byte {
	buf := make([]byte, migrationTicketBodyLen)
	binary.BigEndian.PutUint64(buf[0:8], t.TicketID)
	binary.BigEndian.PutUint32(buf[8:12], t.StreamID)
	binary.BigEndian.PutUint64(buf[12:20], t.SendOffset)
	binary.BigEndian.PutUint64(buf[20:28], t.RecvOffset)
	binary.BigEndian.PutUint64(buf[28:36], uint64(t.ExpiryUnixMs))
	copy(buf[36:68], t.StreamSecret[:])
	return buf
}
