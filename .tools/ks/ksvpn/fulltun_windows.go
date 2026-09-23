//go:build windows

package main

// fulltun_windows.go — автонастройка маршрутов «полного VPN» на Windows.
//
// Порядок критичен: СНАЧАЛА /32 до ноды через ФИЗИЧЕСКИЙ шлюз (иначе
// проводные датаграммы самого туннеля уходят в туннель — петля; именно она
// дала взрыв счётчиков в полевом прогоне владельца 2026-09-01), затем
// сплит-дефолт 0.0.0.0/1 + 128.0.0.0/1 через TUN (перекрывают дефолт, не
// удаляя его — route.exe не даёт второй 0.0.0.0/0: «объект уже существует»),
// плюс /32 до приватных DNS (DNS=роутер иначе уйдёт в туннель и умрёт).
// По Ctrl+C всё снимается. Fail-closed: шлюз не найден — маршруты не трогаем.

import (
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

// setupFullTun ставит маршруты и возвращает функцию отката (вызвать при выходе).
func setupFullTun(peerHost, tunCIDR string, listenPort int) func() {
	noop := func() {}
	tunIP, _, err := net.ParseCIDR(tunCIDR)
	if err != nil {
		log.Printf("fulltun: плохой -tunip %q: %v — маршруты НЕ трогаю", tunCIDR, err)
		return noop
	}
	gw := physicalGateway()
	if gw == nil {
		log.Printf("fulltun: физический шлюз не найден — маршруты НЕ трогаю (fail-closed)")
		return noop
	}
	dns := privateDNS()
	log.Printf("fulltun: физический шлюз %s; нода %s идёт напрямую, остальное — в туннель", gw, peerHost)

	run := func(args ...string) bool {
		if out, err := exec.Command("route", args...).CombinedOutput(); err != nil {
			log.Printf("fulltun: route %s → %v (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
			return false
		}
		return true
	}
	del := func() { // идемпотентно: удаление несуществующего игнорируем
		exec.Command("route", "delete", peerHost).Run()
		for _, d := range dns {
			exec.Command("route", "delete", d).Run()
		}
		exec.Command("route", "delete", "0.0.0.0", "mask", "128.0.0.0").Run()
		exec.Command("route", "delete", "128.0.0.0", "mask", "128.0.0.0").Run()
		exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=ks-vpn-in").Run()
	}

	del() // зачистка после возможного прошлого падения
	ok := run("add", peerHost, "mask", "255.255.255.255", gw.String(), "metric", "1")
	for _, d := range dns {
		run("add", d, "mask", "255.255.255.255", gw.String(), "metric", "1")
	}
	ok = run("add", "0.0.0.0", "mask", "128.0.0.0", tunIP.String(), "metric", "1") && ok
	ok = run("add", "128.0.0.0", "mask", "128.0.0.0", tunIP.String(), "metric", "1") && ok
	// входящие ответы ноды не должны резаться брандмауэром
	if out, err := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name=ks-vpn-in", "dir=in", "action=allow", "protocol=UDP",
		"localport="+strconv.Itoa(listenPort)).CombinedOutput(); err != nil {
		log.Printf("fulltun: правило брандмауэра: %v (%s) — если уже есть, это нормально", err, strings.TrimSpace(string(out)))
	}
	if !ok {
		log.Printf("fulltun: НЕ все маршруты встали (см. выше) — туннель работает только для 10.99.0.0/24")
	} else {
		log.Printf("fulltun: маршруты встали (весь трафик в туннель; откат — по Ctrl+C)")
	}
	return func() {
		del()
		log.Printf("fulltun: маршруты сняты")
	}
}

// physicalGateway — NextHop текущего дефолтного маршрута через PowerShell
// (локаль-независимо: route print на русской Windows парсить нельзя).
func physicalGateway() net.IP {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop").Output()
	if err != nil {
		log.Printf("fulltun: Get-NetRoute: %v", err)
		return nil
	}
	ip := net.ParseIP(strings.TrimSpace(string(out)))
	if ip == nil || ip.To4() == nil {
		log.Printf("fulltun: неожиданный ответ шлюза %q", strings.TrimSpace(string(out)))
		return nil
	}
	return ip
}

// privateDNS — приватные IPv4 DNS-серверы машины: DNS домашнего роутера надо
// оставить снаружи туннеля (его /32 через физический шлюз), иначе резолв умрёт.
func privateDNS() []string {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"(Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses").Output()
	if err != nil {
		return nil
	}
	var res []string
	seen := map[string]bool{}
	for _, ln := range strings.Split(string(out), "\n") {
		s := strings.TrimSpace(ln)
		ip := net.ParseIP(s)
		if ip == nil || !isPrivate(ip) || seen[s] {
			continue
		}
		seen[s] = true
		res = append(res, s)
	}
	return res
}

func isPrivate(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	switch {
	case v4[0] == 10, v4[0] == 192 && v4[1] == 168, v4[0] == 169 && v4[1] == 254:
		return true
	case v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31:
		return true
	}
	return false
}
