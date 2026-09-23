//go:build !linux

package main

// freebind_other.go — IPV6_FREEBIND нужен только ноде на Linux (anyip-пул);
// на остальных платформах — no-op.

import "net"

func setV6Freebind(sock *net.UDPConn) {}
