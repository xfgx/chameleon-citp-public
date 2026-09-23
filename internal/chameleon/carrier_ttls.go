package chameleon

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv4"
)

// carrier_ttls.go — адаптер Sub-Horizon TTL Smuggling к интерфейсу Carrier.
//
// TTLSCarrier — датаграммный несущий транспорт CITP v3.0: каждый кадр
// шифруется AES-256-GCM (ключ из HKDF по PSK) и уходит UDP-датаграммой с
// фиксированным IP TTL в сторону decoy-адреса; сопряжённый TAP-узел на пути
// читает кадры, а дальше него пакет уничтожается маршрутизатором (TTL
// Expired), не достигая decoy.
//
// Как и refraction carrier, требует инфраструктуры (on-path TAP-узел). Без
// него Dial работает, но Receive получит только тот трафик, который сеть
// реально доставила на сокет (например loopback в selftest/тестах).

// TTLSConfig — конфигурация TTLSCarrier.
type TTLSConfig struct {
	Secret string `json:"secret"` // общий PSK для HKDF
	TTL    int    `json:"ttl"`    // исходящий IP TTL (ровно до TAP-узла)
}

// TTLSCarrier реализует Carrier поверх Sub-Horizon TTL Smuggling.
type TTLSCarrier struct {
	cfg     TTLSConfig
	sm      *TTLSmuggler
	pc      *ipv4.PacketConn
	dst     *net.UDPAddr
	sendSeq uint64
	mu      sync.Mutex // сериализует запись кадров
}

// NewTTLSCarrier создаёт carrier; Dial обязателен перед отправкой.
func NewTTLSCarrier(cfg TTLSConfig) *TTLSCarrier {
	return &TTLSCarrier{cfg: cfg}
}

func (c *TTLSCarrier) Name() string { return "ttl-subhorizon" }

func (c *TTLSCarrier) Capabilities() CarrierCapabilities {
	return CarrierCapabilities{
		Name:                "ttl-subhorizon",
		ReliableStreams:     false, // UDP: надёжность эмулируется уровнем CITP
		UnreliableDatagrams: true,
		IndependentStreams:  true, // каждая датаграмма независима
		PathMigration:       false,
		MaxFrameSize:        TTLSMaxPayload,
	}
}

// Dial готовит UDP-сокет, фиксирует TTL и запоминает decoy-адрес назначения.
// addr — "host:port" decoy-цели (например "1.1.1.1:443").
func (c *TTLSCarrier) Dial(_ context.Context, addr string) error {
	if c.cfg.Secret == "" {
		return errors.New("ttls carrier requires a shared secret (PSK)")
	}
	ttl := c.cfg.TTL
	if ttl <= 0 || ttl > 255 {
		return errors.New("ttls carrier requires TTL in 1..255")
	}
	sm, err := NewTTLSmuggler(c.cfg.Secret)
	if err != nil {
		return err
	}
	raddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return err
	}
	pc := ipv4.NewPacketConn(conn)
	if err := pc.SetTTL(ttl); err != nil {
		_ = conn.Close()
		return err
	}
	_ = pc.SetControlMessage(ipv4.FlagTTL|ipv4.FlagDst|ipv4.FlagInterface, true)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.sm = sm
	c.pc = pc
	c.dst = raddr
	return nil
}

// SendDatagram шифрует msg одним кадром и отправляет с фиксированным TTL.
func (c *TTLSCarrier) SendDatagram(_ uint32, msg []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pc == nil || c.sm == nil {
		return errors.New("ttls carrier not connected")
	}
	seq := atomic.AddUint64(&c.sendSeq, 1)
	frame, err := c.sm.Encrypt(seq, msg)
	if err != nil {
		return err
	}
	_, err = c.pc.WriteTo(frame, &ipv4.ControlMessage{TTL: c.cfg.TTL}, c.dst)
	return err
}

// SendControl отображает управляющие сообщения на датаграммный канал
// (как TCPCarrier отображает датаграммы на поток — в обратную сторону).
func (c *TTLSCarrier) SendControl(msg []byte) error { return c.SendDatagram(0, msg) }

// SendReliable — best-effort маппинг: надёжность обеспечивает уровень CITP
// (повторы/expire), сам транспорт гарантий не даёт.
func (c *TTLSCarrier) SendReliable(streamID uint32, msg []byte) error {
	return c.SendDatagram(streamID, msg)
}

// Receive читает сокет, отбрасывает чужой шум без magic/AuthTag и возвращает
// первый подлинный кадр.
func (c *TTLSCarrier) Receive() ([]byte, error) {
	if c.pc == nil || c.sm == nil {
		return nil, errors.New("ttls carrier not connected")
	}
	buf := make([]byte, 65535)
	for {
		n, _, _, err := c.pc.ReadFrom(buf)
		if err != nil {
			return nil, err
		}
		_, pt, err := c.sm.Decrypt(buf[:n])
		if err != nil {
			continue // фоновый шум / чужие пакеты
		}
		return pt, nil
	}
}

// Close закрывает сокет carrier'а.
func (c *TTLSCarrier) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pc != nil {
		err := c.pc.Close()
		c.pc = nil
		return err
	}
	return nil
}

// SetReadDeadline пробрасывает дедлайн чтения на сокет carrier'а
// (демо-клиенты, аккуратный выход из Receive).
func (c *TTLSCarrier) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pc == nil {
		return errors.New("ttls carrier not connected")
	}
	return c.pc.SetReadDeadline(t)
}
