package chameleon

// cf_profiler_helpers.go — support functions for the DPI profiler.

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"syscall"
	"time"
)

// tlsHandshakeClient performs a real TLS handshake as a client with the given
// ServerName (SNI). Returns the connection or the handshake error. The SNI is
// caller-supplied (operator-curated); the profiler never invents banned SNIs.
func tlsHandshakeClient(conn net.Conn, sni string) (*tls.Conn, error) {
	tc := tls.Client(conn, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // we only care whether the handshake completes
		MinVersion:         tls.VersionTLS12,
	})
	if err := tc.Handshake(); err != nil {
		return nil, err
	}
	return tc, nil
}

// tracerouteRSTScan does a TTL-based scan toward host to localize an on-path
// middlebox that injects TCP RSTs. It sends TCP SYNs with increasing TTL and
// classifies the response (ICMP TIME EXCEEDED = normal hop; TCP RST = a censor
// reacting at that hop). Requires CAP_NET_RAW on Linux; degrades gracefully.
func tracerouteRSTScan(ctx context.Context, host string, timeout time.Duration) (int, string) {
	ip, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return -1, "resolve failed: " + err.Error()
	}

	// Raw socket needs privileges. Try and degrade on EPERM/EACCES.
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return -1, "raw socket unavailable (needs CAP_NET_RAW/root): " + err.Error()
	}
	_ = syscall.Close(fd)
	_ = ip

	// NOTE: a full TCP-SYN traceroute with RST classification requires raw IP
	// crafting and a raw ICMP listener (golang.org/x/net/icmp). To keep this
	// dependency-free and safe-by-default, we implement the discovery skeleton
	// and return "not localized" rather than shipping a raw packet crafter.
	return -1, "TTL localization requires a privileged raw-socket ICMP listener (golang.org/x/net/icmp); not enabled in safe-by-default build. Run with CAP_NET_RAW and wire golang.org/x/net/icmp to enable."
}

// fmtHop renders a hop line for diagnostics.
func fmtHop(ttl int, ip string) string { return fmt.Sprintf("ttl=%d ip=%s", ttl, ip) }
