//go:build windows

package main

// tun_windows.go — Wintun-реализация TUN для Windows-клиента ks-vpn.
//
// Статус честно: компилируется GOOS=windows против golang.zx2c4.com/wintun
// (официальный биндинг, уже в go.mod).
//
// v2 (2026-09-01, по полевому логу владельца): ReceivePacket() неблокирующий —
// на пустом ring-буфере возвращает ERROR_NO_MORE_ITEMS ("No more data is
// available"); v1 отдавал её наверх и клиент завершался на старте. Теперь
// Read() блокируется на ReadWaitEvent() (правильный паттерн wintun), а Write()
// коротко ретраит при переполнении ring передачи. Живой прогон на
// Windows-хосте — за владельцем.

import (
	"errors"
	"log"
	"net"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

// wtun — tunDevice поверх Wintun ring buffer.
type wtun struct {
	ad      *wintun.Adapter
	session wintun.Session
}

// openTUN — создать (или переоткрыть осиротевший) адаптер и сессию; адрес
// назначается через netsh (Wintun адреса не выставляет; нужны права админа).
func openTUN(name, ipCIDR string, allowV6 bool) (tunDevice, string, error) {
	ad, err := wintun.CreateAdapter(name, "KS-VPN", nil)
	if err != nil {
		ad, err = wintun.OpenAdapter(name)
		if err != nil {
			return nil, "", err
		}
	}
	sess, err := ad.StartSession(0x800000) // ring 8 MiB
	if err != nil {
		ad.Close()
		return nil, "", err
	}
	if ip, ipnet, e := net.ParseCIDR(ipCIDR); e == nil {
		mask := net.IP(ipnet.Mask).String()
		if out, e2 := exec.Command("netsh", "interface", "ip", "set", "address",
			"name="+name, "static", ip.String(), mask, "none", "1").CombinedOutput(); e2 != nil {
			log.Printf("netsh set address %s: %v (%s) — назначь адрес вручную", ipCIDR, e2, out)
		}
	}
	// MTU как у ноды (1300): иначе большие TLS-пакеты фрагментировались бы в провод
	if out, e3 := exec.Command("netsh", "interface", "ipv4", "set", "subinterface",
		name, "mtu=1300", "store=active").CombinedOutput(); e3 != nil {
		log.Printf("netsh mtu 1300 на %s: %v (%s)", name, e3, strings.TrimSpace(string(out)))
	}
	return &wtun{ad: ad, session: sess}, name, nil
}

// Read — БЛОКИРУЮЩЕЕ чтение: при пустом ring-буфере (ERROR_NO_MORE_ITEMS)
// ждём ReadWaitEvent, а не возвращаем ошибку вызывающему.
func (w *wtun) Read(p []byte) (int, error) {
	for {
		pkt, err := w.session.ReceivePacket()
		if err == nil {
			n := copy(p, pkt)
			w.session.ReleaseReceivePacket(pkt)
			return n, nil
		}
		if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
			windows.WaitForSingleObject(w.session.ReadWaitEvent(), windows.INFINITE)
			continue
		}
		return 0, err
	}
}

// Write — запись пакета; при переполнении ring передачи — короткие повторы
// (до 100×1 мс), дальше — честная ошибка: пакет отброшен, TCP выше перешлёт.
func (w *wtun) Write(p []byte) (int, error) {
	var err error
	var pkt []byte
	for i := 0; i < 100; i++ {
		pkt, err = w.session.AllocateSendPacket(len(p))
		if err == nil {
			copy(pkt, p)
			w.session.SendPacket(pkt)
			return len(p), nil
		}
		time.Sleep(time.Millisecond)
	}
	return 0, err
}

func (w *wtun) Close() error {
	w.session.End()
	return w.ad.Close()
}
