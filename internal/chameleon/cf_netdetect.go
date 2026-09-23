package chameleon

// cf_netdetect.go — adaptive IP auto-detection for Control Fabric.
//
// No hardcoded addresses: the node IP is discovered from the machine the
// process runs on, and the PC (client) IP is discovered the same way on the
// client side. Both use the standard "UDP dial to a public resolver" trick
// (no packets are actually sent) with a fallback to scanning local
// interfaces. Operators can override detection with CITP_NODE_IP /
// CITP_PC_IP environment variables.

import (
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	detectedNodeIP   string
	detectedNodeOnce sync.Once
	detectedPCIP     string
	detectedPCOnce   sync.Once
)

// DetectNodeIP returns the primary routable IPv4 of this node, discovered at
// runtime. Override with the CITP_NODE_IP environment variable. Returns ""
// only if the machine has no non-loopback IPv4 at all.
func DetectNodeIP() string {
	if v := strings.TrimSpace(os.Getenv("CITP_NODE_IP")); v != "" {
		return v
	}
	detectedNodeOnce.Do(func() { detectedNodeIP = detectOutboundIPv4() })
	return detectedNodeIP
}

// DetectPCIP returns the primary routable IPv4 of the client PC, discovered
// the same adaptive way. Override with CITP_PC_IP. On the server side the
// connected peer address is always preferred (see ControlPeerIP).
func DetectPCIP() string {
	if v := strings.TrimSpace(os.Getenv("CITP_PC_IP")); v != "" {
		return v
	}
	detectedPCOnce.Do(func() { detectedPCIP = detectOutboundIPv4() })
	return detectedPCIP
}

// ControlPeerIP extracts the IP of the connected VPN client from its socket.
// This is how the node learns the PC address automatically per session.
func ControlPeerIP(c net.Conn) string {
	if c == nil {
		return ""
	}
	if host, _, err := net.SplitHostPort(c.RemoteAddr().String()); err == nil {
		return host
	}
	return c.RemoteAddr().String()
}

// detectOutboundIPv4 learns the local source address the OS would use to
// reach the internet. The UDP "dial" sends no packets; it only resolves the
// route. Falls back to scanning interfaces when offline.
func detectOutboundIPv4() string {
	for _, target := range []string{"1.1.1.1:53", "8.8.8.8:53"} {
		conn, err := net.DialTimeout("udp", target, 500*time.Millisecond)
		if err == nil {
			if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
				_ = conn.Close()
				if ip4 := addr.IP.To4(); ip4 != nil && !ip4.IsLoopback() {
					return ip4.String()
				}
			} else {
				_ = conn.Close()
			}
		}
	}
	return FirstNonLoopbackIPv4()
}

// FirstNonLoopbackIPv4 scans local interfaces for the first usable IPv4.
func FirstNonLoopbackIPv4() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip4 := ip.To4(); ip4 != nil && !ip4.IsLoopback() && !ip4.IsLinkLocalUnicast() {
				return ip4.String()
			}
		}
	}
	return ""
}
