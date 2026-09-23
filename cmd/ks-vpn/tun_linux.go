//go:build linux

package main

import (
	"encoding/binary"
	"net"
	"os"
	"syscall"
	"unsafe"
)

const (
	iffTUN    = 0x0001
	iffNoPI   = 0x1000
	tunsetiff = 0x400454ca

	socsifflags   = 0x8914
	socsifaddr    = 0x8916
	socsifmtu     = 0x8922
	socsifnetmask = 0x891c
	iffUp         = 0x1
	iffRunning    = 0x40
)

// ifreqIoctl — ifreq-ioctl на контрольном сокете (без внешних бинарей ip/sysctl).
func ifreqIoctl(name string, cmd uintptr, setup func(*[40]byte)) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	var ifr [40]byte
	copy(ifr[:16], name)
	setup(&ifr)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), cmd, uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return errno
	}
	return nil
}

// configIface — поднять интерфейс + адрес + MTU чистым ioctl (самодостаточно,
// работает в минимальных окружениях без iproute2).
func configIface(name, ipCIDR string, mtu int) error {
	ip, ipnet, err := net.ParseCIDR(ipCIDR)
	if err != nil {
		return err
	}
	if err := ifreqIoctl(name, socsifmtu, func(ifr *[40]byte) {
		binary.LittleEndian.PutUint32(ifr[16:20], uint32(mtu))
	}); err != nil {
		return err
	}
	if err := ifreqIoctl(name, socsifaddr, func(ifr *[40]byte) {
		binary.LittleEndian.PutUint16(ifr[16:18], syscall.AF_INET)
		copy(ifr[20:24], ip.To4())
	}); err != nil {
		return err
	}
	if err := ifreqIoctl(name, socsifnetmask, func(ifr *[40]byte) {
		binary.LittleEndian.PutUint16(ifr[16:18], syscall.AF_INET)
		copy(ifr[20:24], ipnet.Mask)
	}); err != nil {
		return err
	}
	if err := ifreqIoctl(name, socsifflags, func(ifr *[40]byte) {
		binary.LittleEndian.PutUint16(ifr[16:18], iffUp|iffRunning)
	}); err != nil {
		return err
	}
	return nil
}

// openTUN — создать TUN (Linux, raw IP без PI-заголовка) и настроить без внешних
// команд: MTU/адрес/поднятие через ioctl. По умолчанию IPv6 на адаптере
// глушится (disable_ipv6=1: нет link-local/RS-шума) — кроме режима allowV6
// (флаг -tunv6): ноды транзита обязаны пропускать v6-пакеты туннеля, иначе
// ядро их отбрасывает прямо на интерфейсе.
func openTUN(name, ipCIDR string, allowV6 bool) (tunDevice, string, error) {
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		return nil, "", err
	}
	var ifr [40]byte
	copy(ifr[:16], name)
	binary.LittleEndian.PutUint16(ifr[16:18], iffTUN|iffNoPI)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), tunsetiff, uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		syscall.Close(fd)
		return nil, "", errno
	}
	in := name
	if z := indexByte(ifr[:16], 0); z >= 0 {
		in = string(ifr[:z])
	}
	f := os.NewFile(uintptr(fd), "tun")
	if !allowV6 {
		// глушим IPv6-RS шум на старте (через /proc)
		os.WriteFile("/proc/sys/net/ipv6/conf/"+in+"/disable_ipv6", []byte("1"), 0644)
	}
	if err := configIface(in, ipCIDR, 1300); err != nil { // MTU 1300: пакет целиком в один CDT-фрагмент
		syscall.Close(fd)
		return nil, "", err
	}
	return f, in, nil
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}
