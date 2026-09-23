package chameleon

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// E2E против реальной ноды: UDP-релей DNS через туннель.
func TestE2EUDPRelay(t *testing.T) {
	if testing.Short() {
		t.Skip("ручной e2e")
	}
	conn, err := DialNode("198.51.100.10:8443", "hCs_ISiKS_DPbsA3mD2xhcHaIDa9d1G_AbYGBkBlAnc", "u8YsDqXXbSpHtCtiFLu92OB3_DFRj1g9GE3OEGpHB3s", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	m := NewMuxClient(conn)
	st, err := m.OpenUDP("8.8.8.8:53")
	if err != nil {
		t.Fatal(err)
	}
	// DNS-запрос A google.com
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	frame := append([]byte{0, byte(len(q))}, q...)
	if _, err := st.Write(frame); err != nil {
		t.Fatal(err)
	}
	st.m.Conn().SetDeadline(time.Now().Add(10 * time.Second))
	lb := make([]byte, 2)
	if _, err := io.ReadFull(st, lb); err != nil {
		t.Fatal(err)
	}
	n := int(binary.BigEndian.Uint16(lb))
	resp := make([]byte, n)
	if _, err := io.ReadFull(st, resp); err != nil {
		t.Fatal(err)
	}
	ip := net.IP(resp[n-4 : n])
	t.Logf("DNS ответ через туннель: %d байт, последний A: %s", n, ip)
}
