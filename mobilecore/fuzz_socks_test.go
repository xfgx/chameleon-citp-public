package mobilecore

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

type fuzzAddr string

func (a fuzzAddr) Network() string { return "fuzz" }
func (a fuzzAddr) String() string  { return string(a) }

type fuzzConn struct{ *bytes.Reader }

func (c *fuzzConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *fuzzConn) Close() error                     { return nil }
func (c *fuzzConn) LocalAddr() net.Addr              { return fuzzAddr("local") }
func (c *fuzzConn) RemoteAddr() net.Addr             { return fuzzAddr("remote") }
func (c *fuzzConn) SetDeadline(time.Time) error      { return nil }
func (c *fuzzConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fuzzConn) SetWriteDeadline(time.Time) error { return nil }

func FuzzReadSocksAddr(f *testing.F) {
	f.Add(byte(0x01), []byte{1, 1, 1, 1, 1, 187})
	f.Add(byte(0x03), append([]byte{11}, append([]byte("example.com"), 0, 80)...))
	f.Add(byte(0x04), make([]byte, 18))
	f.Fuzz(func(t *testing.T, atyp byte, data []byte) {
		if len(data) > 1024 {
			data = data[:1024]
		}
		_, _ = readSocksAddr(&fuzzConn{Reader: bytes.NewReader(data)}, atyp)
	})
}

var _ io.Reader = (*fuzzConn)(nil)
