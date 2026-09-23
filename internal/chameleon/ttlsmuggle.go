package chameleon

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/ipv4"
)

// ttlsmuggle.go — CITP v3.0: Sub-Horizon TTL Smuggling.
//
// Клиент отправляет зашифрованные кадры в сторону легального decoy-адреса с
// точно выставленным IP TTL: пакет проходит ТСПУ и транзитный TAP-узел, а за
// ним TTL обнуляется и пакет уничтожается маршрутизатором, не достигая decoy.
// TAP-узел (сопряжённая нода) слушает UDP-порт, извлекает кадр и проверяет
// AuthTag. ТСПУ видит короткоживущий «шум» к легальному хосту; decoy не видит
// ничего.
//
// Кадр на проводе (UDP payload):
//
//	[4 байта: Magic "TTLS" 0x54544C53]
//	[8 байт:  Seq uint64]
//	[12 байт: Nonce]
//	[N байт:  AES-256-GCM ciphertext || 16 байт AuthTag]
//
// AAD = заголовок (magic || seq || nonce): подделка seq/nonce ломает GCM.
//
// Ограничение (как и у refraction carrier): нужен сопряжённый on-path узел.
// Без инфраструктуры режим работает как локальная проверка (selftest).

const (
	// TTLSMagic — сигнатура кадра Sub-Horizon передачи ("TTLS").
	TTLSMagic uint32 = 0x54544C53
	// TTLSHeaderSize — magic(4) || seq(8) || nonce(12).
	TTLSHeaderSize = 4 + 8 + 12
	// TTLSTagSize — размер AuthTag AES-GCM.
	TTLSTagSize = 16
	// TTLSMaxPayload — максимум полезной нагрузки кадра:
	// 65507 (UDP max в IPv4) минус заголовок и тег.
	TTLSMaxPayload = 65507 - TTLSHeaderSize - TTLSTagSize
)

var (
	// ErrTTLSShort — кадр короче минимально возможного (заголовок + тег).
	ErrTTLSShort = errors.New("ttls: кадр короче заголовка+тега")
	// ErrTTLSPayload — полезная нагрузка превышает TTLSMaxPayload.
	ErrTTLSPayload  = errors.New("ttls: полезная нагрузка превышает максимум")
	errTTLSBadMagic = errors.New("ttls: неверный magic (чужой трафик)")
	errTTLSAuth     = errors.New("ttls: ошибка аутентификации GCM")
)

// TTLSmuggler шифрует и расшифровывает кадры Sub-Horizon передачи.
type TTLSmuggler struct {
	aead cipher.AEAD
}

// NewTTLSmuggler выводит 32-байтовый ключ AES-256 из общего секрета (PSK)
// через HKDF-SHA256 с меткой "chameleon-ttl-smuggle".
func NewTTLSmuggler(secret string) (*TTLSmuggler, error) {
	kdf := hkdf.New(sha256.New, []byte(secret), nil, []byte("chameleon-ttl-smuggle"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &TTLSmuggler{aead: aead}, nil
}

// Encrypt собирает и зашифровывает кадр с заданным порядковым номером.
func (s *TTLSmuggler) Encrypt(seq uint64, payload []byte) ([]byte, error) {
	if len(payload) > TTLSMaxPayload {
		return nil, fmt.Errorf("%w: %d > %d", ErrTTLSPayload, len(payload), TTLSMaxPayload)
	}
	var nonce [12]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}
	header := make([]byte, TTLSHeaderSize)
	binary.BigEndian.PutUint32(header[0:4], TTLSMagic)
	binary.BigEndian.PutUint64(header[4:12], seq)
	copy(header[12:24], nonce[:])
	ct := s.aead.Seal(nil, nonce[:], payload, header)
	return append(header, ct...), nil
}

// Decrypt проверяет magic и AuthTag, возвращает seq и открытый текст.
func (s *TTLSmuggler) Decrypt(packet []byte) (uint64, []byte, error) {
	if len(packet) < TTLSHeaderSize+TTLSTagSize {
		return 0, nil, ErrTTLSShort
	}
	if binary.BigEndian.Uint32(packet[0:4]) != TTLSMagic {
		return 0, nil, errTTLSBadMagic
	}
	seq := binary.BigEndian.Uint64(packet[4:12])
	nonce := packet[12:24]
	header := packet[:TTLSHeaderSize]
	ct := packet[TTLSHeaderSize:]
	pt, err := s.aead.Open(nil, nonce, ct, header)
	if err != nil {
		return 0, nil, errTTLSAuth
	}
	return seq, pt, nil
}

// TTLSender отправляет кадры с фиксированным TTL в сторону decoy-адреса.
type TTLSender struct {
	sm  *TTLSmuggler
	pc  *ipv4.PacketConn
	dst *net.UDPAddr
	ttl int
}

// NewTTLSender открывает UDP-сокет и фиксирует исходящий IP TTL.
// dstAddr — "host:port" decoy-цели (например "1.1.1.1:443").
func NewTTLSender(sm *TTLSmuggler, dstAddr string, ttl int) (*TTLSender, error) {
	raddr, err := net.ResolveUDPAddr("udp4", dstAddr)
	if err != nil {
		return nil, err
	}
	c, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, err
	}
	pc := ipv4.NewPacketConn(c)
	if err := pc.SetTTL(ttl); err != nil {
		_ = c.Close()
		return nil, err
	}
	return &TTLSender{sm: sm, pc: pc, dst: raddr, ttl: ttl}, nil
}

// Send шифрует и отправляет один кадр; TTL продублирован в ControlMessage,
// чтобы ядро гарантированно выставило его на исходящем пакете.
func (s *TTLSender) Send(seq uint64, payload []byte) (int, error) {
	frame, err := s.sm.Encrypt(seq, payload)
	if err != nil {
		return 0, err
	}
	cm := &ipv4.ControlMessage{TTL: s.ttl}
	return s.pc.WriteTo(frame, cm, s.dst)
}

// Close закрывает сокет отправителя.
func (s *TTLSender) Close() error { return s.pc.Close() }

// TTLFrame — принятый и расшифрованный фантомный кадр.
type TTLFrame struct {
	Seq     uint64
	Payload []byte
	Src     net.Addr
	TTL     int // остаточный TTL на приёмнике (0 = стек не сообщил)
	Size    int // размер кадра на проводе
}

// TTLReceiver — TAP-узел: слушает UDP-порт и извлекает свои кадры из шума.
type TTLReceiver struct {
	sm *TTLSmuggler
	pc *ipv4.PacketConn
}

// NewTTLReceiver поднимает прослушивание и включает чтение TTL из IP-заголовка.
// listenAddr — "ip:port" (например "0.0.0.0:443").
func NewTTLReceiver(sm *TTLSmuggler, listenAddr string) (*TTLReceiver, error) {
	laddr, err := net.ResolveUDPAddr("udp4", listenAddr)
	if err != nil {
		return nil, err
	}
	c, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		return nil, err
	}
	pc := ipv4.NewPacketConn(c)
	if err := pc.SetControlMessage(ipv4.FlagTTL|ipv4.FlagDst|ipv4.FlagInterface, true); err != nil {
		_ = c.Close()
		return nil, err
	}
	return &TTLReceiver{sm: sm, pc: pc}, nil
}

// LocalAddr возвращает фактический адрес прослушивания (полезно при порте :0).
func (r *TTLReceiver) LocalAddr() *net.UDPAddr {
	return r.pc.LocalAddr().(*net.UDPAddr)
}

// SetReadDeadline пробрасывает дедлайн на сокет (тесты, аккуратный выход).
func (r *TTLReceiver) SetReadDeadline(t time.Time) error {
	return r.pc.SetReadDeadline(t)
}

// ReadFrame читает сокет, отбрасывает чужой шум без magic/AuthTag и возвращает
// первый подлинный кадр. Ошибка возвращается только при ошибке сокета.
func (r *TTLReceiver) ReadFrame() (*TTLFrame, error) {
	buf := make([]byte, 65535)
	for {
		n, cm, src, err := r.pc.ReadFrom(buf)
		if err != nil {
			return nil, err
		}
		seq, pt, err := r.sm.Decrypt(buf[:n])
		if err != nil {
			continue // фоновый шум / чужие пакеты
		}
		ttl := 0
		if cm != nil {
			ttl = cm.TTL
		}
		return &TTLFrame{Seq: seq, Payload: pt, Src: src, TTL: ttl, Size: n}, nil
	}
}

// Close закрывает сокет приёмника.
func (r *TTLReceiver) Close() error { return r.pc.Close() }

// SendTo шифрует и отправляет кадр конкретному адресу через сокет приёмника.
// Используется для ответов клиентам (эхо/данные). ttl здесь полный (напр. 64):
// ответ обязан ДОЙТИ до клиента — в отличие от скрытого направления
// клиент->нода, где пакет срывается по TTL за TAP-узлом.
func (r *TTLReceiver) SendTo(addr net.Addr, seq uint64, payload []byte, ttl int) (int, error) {
	frame, err := r.sm.Encrypt(seq, payload)
	if err != nil {
		return 0, err
	}
	return r.pc.WriteTo(frame, &ipv4.ControlMessage{TTL: ttl}, addr)
}
