//go:build linux

package main

// wiresrc6_linux.go — исходные адреса провода на Linux (стенды/ноды).
//
// На Linux поадресное назначение не нужно: IPV6_FREEBIND (тот же sockopt 78,
// что и в freebind_linux.go для anyip-пула ноды) разрешает bind на адрес из
// маршрутизуемого префикса без его назначения на интерфейс. Граница
// честная: маршрут на префикс обеспечивает обвязка хоста/стенда.
//
// Detect не угадывает префикс по RA (это делает Windows-часть): берётся
// первый глобальный адрес не-TUN интерфейса с маской шире /128; нет
// такого — честная ошибка (стенды всегда задают -wire6src <CIDR> явно).

import (
	"context"
	"net"
	"syscall"
)

type srcMgrLinux struct{}

func newSrcMgr6() srcMgr6 { return &srcMgrLinux{} }

func (m *srcMgrLinux) Detect(tunIfname string) (*net.IPNet, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, ifc := range ifaces {
		if ifc.Name == tunIfname || ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() != nil || !ipn.IP.IsGlobalUnicast() {
				continue
			}
			ones, bits := ipn.Mask.Size()
			if bits != 128 || ones >= 128 {
				continue
			}
			return &net.IPNet{IP: ipn.IP.Mask(ipn.Mask), Mask: ipn.Mask}, nil
		}
	}
	return nil, errNoNativeV6
}

// Listen — bind с IPV6_FREEBIND до привязки адреса (случайный порт).
func (m *srcMgrLinux) Listen(ip net.IP) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6Freebind, 1)
			}); err != nil {
				return err
			}
			return serr
		},
	}
	pc, err := lc.ListenPacket(context.Background(), "udp6", net.JoinHostPort(ip.String(), "0"))
	if err != nil {
		return nil, err
	}
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		return nil, errSrcNoSocks
	}
	return uc, nil
}

// Release — адреса не назначались, снимать нечего.
func (m *srcMgrLinux) Release(ip net.IP) {}
