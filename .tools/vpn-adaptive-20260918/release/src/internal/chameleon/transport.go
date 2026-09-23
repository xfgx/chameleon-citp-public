package chameleon

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Морфящий кадр "Хамелеон" на проводе:
//
//	maskedLen(2) || garbageHeader(headerLen) || AEAD ciphertext || garbagePad(padLen)
//
// maskedLen  — длина шифротекста, XOR-нутая байтами из DRBG.
// headerLen и padLen на каждый кадр генерирует DRBG — приёмник воспроизводит
// тот же поток и знает, сколько байт мусора пропустить. Для внешнего
// наблюдателя: нет ни постоянных префиксов, ни предсказуемых длин, ни
// стабильной структуры — каждый сеанс выглядит по-новому.
//
// DRBG-потоки раздельные по направлениям ("c2s-mask" / "s2c-mask"), иначе
// порядок выборок зависел бы от чередования кадров и стороны рассинхронизировались бы.
const (
	maxPayload   = 65518 // 65519 - 1 байт типа кадра
	frameData    = 0x00
	framePadding = 0x01
)

type Conn struct {
	c              net.Conn
	prof           *Profile
	seed           []byte
	sendAEAD       cipher.AEAD
	recvAEAD       cipher.AEAD
	sendMask       *DRBG
	recvMask       *DRBG
	sendNonce      uint64
	recvNonce      uint64
	sendMu         sync.Mutex   // writeFrame зовут и релей, и CBR-шейпер
	lastSend       atomic.Int64 // для CBR: когда последний раз уходил кадр
	lastUsefulSend atomic.Int64
	pendingSend    atomic.Int64
	closed         atomic.Bool
	traffic        trafficScheduler
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// NewClientConn оборачивает установленное соединение на стороне клиента.
func NewClientConn(c net.Conn, s *Session) (*Conn, error) {
	return newConn(c, s, "c2s-mask", "s2c-mask")
}

// NewServerConn оборачивает установленное соединение на стороне сервера.
func NewServerConn(c net.Conn, s *Session) (*Conn, error) {
	return newConn(c, s, "s2c-mask", "c2s-mask")
}

func newConn(c net.Conn, s *Session, sendLabel, recvLabel string) (*Conn, error) {
	send, err := newAEAD(s.SendKey)
	if err != nil {
		return nil, err
	}
	recv, err := newAEAD(s.RecvKey)
	if err != nil {
		return nil, err
	}
	return &Conn{
		c:        c,
		prof:     NewProfile(s.Seed),
		seed:     s.Seed,
		sendAEAD: send,
		recvAEAD: recv,
		sendMask: NewDRBG(s.Seed, sendLabel),
		recvMask: NewDRBG(s.Seed, recvLabel),
	}, nil
}

func nonceFrom(counter uint64) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], counter)
	return n
}

// WriteMessage шифрует и отправляет одно сообщение одним морфящим кадром.
func (c *Conn) WriteMessage(p []byte) error {
	if len(p) > maxPayload {
		return fmt.Errorf("payload %d > max %d", len(p), maxPayload)
	}
	return c.writeFrame(frameData, p)
}

// WritePadding отправляет кадр-заполнитель: на проводе неотличим от данных,
// приёмник молча отбрасывает. Основа паддинга до постоянного битрейта.
func (c *Conn) WritePadding(n int) error {
	if n < 0 {
		return errors.New("transport: negative padding size")
	}
	if n > maxPayload {
		n = maxPayload
	}
	return c.writeFrame(framePadding, make([]byte, n))
}

// LastSendNano — время отправки последнего кадра (для CBR-шейпера).
func (c *Conn) LastSendNano() int64 { return c.lastSend.Load() }

func (c *Conn) writeFrame(typ byte, p []byte) error {
	if typ == frameData {
		c.pendingSend.Add(1)
		defer c.pendingSend.Add(-1)
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	return c.writeFrameLocked(typ, p)
}

func (c *Conn) writeFrameLocked(typ byte, p []byte) error {
	if c.closed.Load() {
		return net.ErrClosed
	}
	if c.sendNonce == ^uint64(0) {
		return errors.New("transport: send nonce exhausted")
	}
	d := c.sendMask
	// Порядок выборок из DRBG фиксирован и одинаков у обеих сторон:
	// mask → headerLen → header → padLen → pad.
	mask := d.Bytes(2)
	headerLen := c.prof.MinHeader + d.Intn(c.prof.HeaderVar)
	header := d.Bytes(headerLen)
	padLen := d.Intn(c.prof.MaxPad + 1)
	pad := d.Bytes(padLen)

	plain := make([]byte, 1+len(p))
	plain[0] = typ
	copy(plain[1:], p)
	ct := c.sendAEAD.Seal(nil, nonceFrom(c.sendNonce), plain, nil)
	c.sendNonce++

	wireLen := uint16(len(ct)) ^ binary.BigEndian.Uint16(mask)
	buf := make([]byte, 0, 2+headerLen+len(ct)+padLen)
	var lb [2]byte
	binary.BigEndian.PutUint16(lb[:], wireLen)
	buf = append(buf, lb[:]...)
	buf = append(buf, header...)
	buf = append(buf, ct...)
	buf = append(buf, pad...)
	n, err := c.c.Write(buf)
	if err == nil && n != len(buf) {
		err = io.ErrShortWrite
	}
	if err != nil {
		// After a partial frame, nonce/mask state cannot be safely reused.
		_ = c.Close()
		return err
	}
	c.lastSend.Store(time.Now().UnixNano())
	return nil
}

// ReadMessage читает и расшифровывает один кадр данных.
// Кадры-паддинг молча пропускаются.
func (c *Conn) ReadMessage() ([]byte, error) {
	for {
		typ, p, err := c.readFrame()
		if err != nil {
			return nil, err
		}
		if typ == framePadding {
			continue
		}
		return p, nil
	}
}

func (c *Conn) readFrame() (byte, []byte, error) {
	if c.recvNonce == ^uint64(0) {
		return 0, nil, errors.New("transport: receive nonce exhausted")
	}
	d := c.recvMask
	var lb [2]byte
	if _, err := io.ReadFull(c.c, lb[:]); err != nil {
		return 0, nil, err
	}
	mask := d.Bytes(2)
	ctLen := int(binary.BigEndian.Uint16(lb[:]) ^ binary.BigEndian.Uint16(mask))
	if ctLen < 16 { // минимум GCM-тег
		return 0, nil, errors.New("desync: подозрительная длина кадра")
	}
	headerLen := c.prof.MinHeader + d.Intn(c.prof.HeaderVar)
	d.Bytes(headerLen) // синхронизируем поток
	if _, err := io.CopyN(io.Discard, c.c, int64(headerLen)); err != nil {
		return 0, nil, err
	}
	ct := make([]byte, ctLen)
	if _, err := io.ReadFull(c.c, ct); err != nil {
		return 0, nil, err
	}
	padLen := d.Intn(c.prof.MaxPad + 1)
	d.Bytes(padLen) // синхронизируем поток
	if _, err := io.CopyN(io.Discard, c.c, int64(padLen)); err != nil {
		return 0, nil, err
	}
	plain, err := c.recvAEAD.Open(nil, nonceFrom(c.recvNonce), ct, nil)
	if err != nil {
		return 0, nil, fmt.Errorf("frame auth failed: %w", err)
	}
	c.recvNonce++
	if len(plain) == 0 {
		return 0, nil, errors.New("пустой кадр без типа")
	}
	return plain[0], plain[1:], nil
}

func (c *Conn) Close() error {
	c.closed.Store(true)
	if c.c == nil {
		return nil
	}
	return c.c.Close()
}

// Проброс дедлайнов на нижележащее соединение.
func (c *Conn) SetDeadline(t time.Time) error      { return c.c.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.c.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.c.SetWriteDeadline(t) }
