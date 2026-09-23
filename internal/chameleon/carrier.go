package chameleon

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// CarrierCapabilities описывает эффективные возможности несущего транспорта.
type CarrierCapabilities struct {
	Name                string `json:"name"`
	ReliableStreams     bool   `json:"reliable_streams"`
	UnreliableDatagrams bool   `json:"unreliable_datagrams"`
	IndependentStreams  bool   `json:"independent_streams"`
	PathMigration       bool   `json:"path_migration"`
	MaxFrameSize        int    `json:"max_frame_size"`
}

// Carrier — абстрактный интерфейс физического несущего транспорта (TCP, QUIC, Raw UDP, WebSockets).
type Carrier interface {
	Name() string
	Capabilities() CarrierCapabilities
	Dial(ctx context.Context, addr string) error
	SendControl(msg []byte) error
	SendReliable(streamID uint32, msg []byte) error
	SendDatagram(streamID uint32, msg []byte) error
	Receive() ([]byte, error)
	Close() error
}

// TCPCarrier — реализация несущего транспорта поверх TCP / Chameleon Opaque Transport.
type TCPCarrier struct {
	conn net.Conn
	mu   sync.Mutex
}

func NewTCPCarrier(c net.Conn) *TCPCarrier {
	return &TCPCarrier{conn: c}
}

func (tc *TCPCarrier) Name() string {
	return "opaque-tcp"
}

func (tc *TCPCarrier) Capabilities() CarrierCapabilities {
	return CarrierCapabilities{
		Name:                "opaque-tcp",
		ReliableStreams:     true,
		UnreliableDatagrams: false, // эмулируются поверх надежного потока
		IndependentStreams:  false, // Head-of-line blocking возможен при потерях TCP
		PathMigration:       false,
		MaxFrameSize:        65535,
	}
}

func (tc *TCPCarrier) Dial(ctx context.Context, addr string) error {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	tc.conn = c
	return nil
}

func (tc *TCPCarrier) SendControl(msg []byte) error {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	if tc.conn == nil {
		return errors.New("carrier not connected")
	}
	_, err := tc.conn.Write(msg)
	return err
}

func (tc *TCPCarrier) SendReliable(streamID uint32, msg []byte) error {
	return tc.SendControl(msg)
}

func (tc *TCPCarrier) SendDatagram(streamID uint32, msg []byte) error {
	return tc.SendControl(msg)
}

func (tc *TCPCarrier) Receive() ([]byte, error) {
	if tc.conn == nil {
		return nil, errors.New("carrier not connected")
	}
	buf := make([]byte, 65535)
	n, err := tc.conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (tc *TCPCarrier) Close() error {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	if tc.conn != nil {
		err := tc.conn.Close()
		tc.conn = nil
		return err
	}
	return nil
}

// VirtualMemory/Profile Config: разделение профилей маскировки от ядра CITP
type ObfuscationProfile struct {
	Name        string        `json:"name"`
	CBRInterval time.Duration `json:"cbr_interval"`
	Jitter      time.Duration `json:"jitter"`
	MinPadding  int           `json:"min_padding"`
	MaxPadding  int           `json:"max_padding"`
	CoverDomain string        `json:"cover_domain"`
}

var DefaultProfiles = map[string]ObfuscationProfile{
	"raw": {
		Name:        "raw-citp",
		CBRInterval: 0,
	},
	"cbr-balanced": {
		Name:        "cbr-balanced",
		CBRInterval: 40 * time.Millisecond,
		Jitter:      8 * time.Millisecond,
		MinPadding:  16,
		MaxPadding:  256,
	},
	"steam-simulation": {
		Name:        "steam-simulation",
		CBRInterval: 25 * time.Millisecond,
		Jitter:      5 * time.Millisecond,
		MinPadding:  64,
		MaxPadding:  1400,
		CoverDomain: "steamcommunity.com",
	},
}
