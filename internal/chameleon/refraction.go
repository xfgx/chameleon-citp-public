package chameleon

import (
	"context"
	"errors"
	"net"
	"time"
)

// RefractionConfig describes an experimental TapDance-class carrier.
//
// The client connects to DecoyAddr/DecoyHost as an ordinary TLS destination.
// A cooperating on-path station may detect a cryptographic tag and switch the
// flow into CITP. Without such infrastructure this carrier is not operational.
type RefractionConfig struct {
	DecoyHost       string        `json:"decoy_host"`
	DecoyAddr       string        `json:"decoy_addr"`
	StationID       string        `json:"station_id"`
	StationPubKey   string        `json:"station_pubkey"`
	TagEpochSeconds int           `json:"tag_epoch_seconds"`
	DialTimeout     time.Duration `json:"dial_timeout"`
}

// RefractionCarrier is a placeholder carrier for refraction-networking style
// deployment. It preserves the existing Carrier interface so CITP can keep the
// mux, policy, DNS-binding and session layers unchanged.
type RefractionCarrier struct {
	cfg  RefractionConfig
	conn net.Conn
}

func NewRefractionCarrier(cfg RefractionConfig) *RefractionCarrier {
	return &RefractionCarrier{cfg: cfg}
}

func (rc *RefractionCarrier) Name() string { return "refraction-tls" }

func (rc *RefractionCarrier) Capabilities() CarrierCapabilities {
	return CarrierCapabilities{
		Name:                "refraction-tls",
		ReliableStreams:     true,
		UnreliableDatagrams: false,
		IndependentStreams:  false,
		PathMigration:       false,
		MaxFrameSize:        65535,
	}
}

func (rc *RefractionCarrier) Dial(ctx context.Context, _ string) error {
	if rc.cfg.DecoyAddr == "" || rc.cfg.DecoyHost == "" || rc.cfg.StationPubKey == "" {
		return errors.New("refraction carrier requires decoy host/address and station public key")
	}
	return errors.New("refraction carrier requires a cooperative on-path station; standalone direct dial is intentionally not implemented")
}

func (rc *RefractionCarrier) SendControl(msg []byte) error {
	if rc.conn == nil {
		return errors.New("refraction carrier not connected")
	}
	_, err := rc.conn.Write(msg)
	return err
}

func (rc *RefractionCarrier) SendReliable(_ uint32, msg []byte) error { return rc.SendControl(msg) }
func (rc *RefractionCarrier) SendDatagram(_ uint32, msg []byte) error { return rc.SendControl(msg) }

func (rc *RefractionCarrier) Receive() ([]byte, error) {
	if rc.conn == nil {
		return nil, errors.New("refraction carrier not connected")
	}
	buf := make([]byte, 65535)
	n, err := rc.conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (rc *RefractionCarrier) Close() error {
	if rc.conn == nil {
		return nil
	}
	err := rc.conn.Close()
	rc.conn = nil
	return err
}
