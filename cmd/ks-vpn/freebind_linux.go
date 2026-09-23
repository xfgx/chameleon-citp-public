//go:build linux

package main

// freebind_linux.go — IPV6_FREEBIND на слушающем сокете ноды: позволяет
// отвечать pktinfo-источником из anyip-пула (пул держится local-роутом на lo,
// без поадресного назначения — ядро иначе режет EINVAL). Пробник в netns
// 2026-09-04: plain=EINVAL, freebind=OK, пакет уходит с адресом пула.
// На v4-путь и на приём не влияет.

import (
	"log"
	"net"
	"syscall"
)

// ipv6Freebind — IPV6_FREEBIND (Linux). В syscall-пакете константы нет.
const ipv6Freebind = 78

func setV6Freebind(sock *net.UDPConn) {
	sc, err := sock.SyscallConn()
	if err != nil {
		log.Printf("IPV6_FREEBIND: SyscallConn: %v", err)
		return
	}
	sc.Control(func(fd uintptr) {
		if err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6Freebind, 1); err != nil {
			log.Printf("IPV6_FREEBIND: %v — ответы с hit-адреса пула не пойдут (будет фолбэк на адрес туннеля)", err)
		}
	})
}
