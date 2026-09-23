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
//
// v3 (2026-09-02, по полевому прогону владельца): ИСПРАВЛЕН КРИТИЧЕСКИЙ БАГ.
// v2 ставила сплит-дефолты со шлюзом = СВОЙ туннельный адрес (10.99.0.1).
// Через собственный адрес маршрутизировать нельзя: Windows не смогла отнести
// next-hop к TUN и привязала оба /1 к ФИЗИЧЕСКОМУ адаптеру
// («Интерфейс 192.168.1.5» в route print). Next-hop на физическом линке
// неразрешим, поэтому стек молча падал назад на настоящий 0.0.0.0/0 через
// роутер: туннель поднят, ping 10.99.0.2 идёт, а весь интернет-трафик уходит
// мимо — внешний IP не меняется. Теперь шлюз сплит-дефолтов = ТУННЕЛЬНЫЙ IP
// НОДЫ (peer, по конвенции .2) и маршрут прибивается к ifIndex TUN явным
// «IF <idx>». Плюс постфактум-верификация: если /1 встали не на TUN — честный
// лог и fail-closed-снятие, чтобы не создавать иллюзию работающего VPN.

import (
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// setupFullTun ставит маршруты и возвращает функцию отката (вызвать при выходе).
func setupFullTun(peerHost, tunCIDR, peerTunIP string, listenPort int) func() {
	noop := func() {}
	tunIP, _, err := net.ParseCIDR(tunCIDR)
	if err != nil {
		log.Printf("fulltun: плохой -tunip %q: %v — маршруты НЕ трогаю", tunCIDR, err)
		return noop
	}
	tun4 := tunIP.To4()
	if tun4 == nil {
		log.Printf("fulltun: -tunip %q не IPv4 — маршруты НЕ трогаю", tunCIDR)
		return noop
	}

	// Шлюз сплит-дефолтов — туннельный адрес НОДЫ, а не свой собственный.
	var tunGW net.IP
	if peerTunIP != "" {
		tunGW = net.ParseIP(peerTunIP).To4()
		if tunGW == nil {
			log.Printf("fulltun: -peertunip %q не IPv4 — маршруты НЕ трогаю (fail-closed)", peerTunIP)
			return noop
		}
	} else {
		tunGW = net.IPv4(tun4[0], tun4[1], tun4[2], 2) // нода по конвенции .2
	}
	if tunGW.Equal(tunIP) {
		log.Printf("fulltun: туннельный шлюз %s совпадает с моим адресом — через себя маршрутизировать нельзя, маршруты НЕ трогаю (fail-closed)", tunGW)
		return noop
	}

	gw := physicalGateway()
	if gw == nil {
		log.Printf("fulltun: физический шлюз не найден — маршруты НЕ трогаю (fail-closed)")
		return noop
	}
	// ifIndex TUN: ищем по своему туннельному адресу — не зависит ни от локали,
	// ни от имени адаптера, которое Windows могла переименовать («ks0 1» и т.п.).
	tunIfIdx := ifIndexByIP(tunIP.String())
	if tunIfIdx <= 0 {
		log.Printf("fulltun: не нашёл ifIndex TUN по адресу %s — маршруты НЕ трогаю (fail-closed)", tunIP)
		return noop
	}
	dns := privateDNS()
	log.Printf("fulltun: физический шлюз %s; нода %s идёт напрямую; туннельный шлюз %s на ifIndex %d — остальное в туннель",
		gw, peerHost, tunGW, tunIfIdx)
	warnProxy()

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
	idx := strconv.Itoa(tunIfIdx)
	ok = run("add", "0.0.0.0", "mask", "128.0.0.0", tunGW.String(), "metric", "1", "IF", idx) && ok
	ok = run("add", "128.0.0.0", "mask", "128.0.0.0", tunGW.String(), "metric", "1", "IF", idx) && ok
	// входящие ответы ноды не должны резаться брандмауэром
	if out, err := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name=ks-vpn-in", "dir=in", "action=allow", "protocol=UDP",
		"localport="+strconv.Itoa(listenPort)).CombinedOutput(); err != nil {
		log.Printf("fulltun: правило брандмауэра: %v (%s) — если уже есть, это нормально", err, strings.TrimSpace(string(out)))
	}
	// проверка, что правило брандмауэра реально на месте
	if out, err := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name=ks-vpn-in").CombinedOutput(); err != nil {
		log.Printf("fulltun: правило брандмауэра НЕ найдено (%v, %s) — входящие ответы могут резаться", err, strings.TrimSpace(string(out)))
	}
	// ВЕРИФИКАЦИЯ: сплит-дефолты обязаны стоять именно на ifIndex TUN. Ровно это
	// и проглядела v2 — маршрут «встал» без ошибки, но на физическом адаптере.
	if ok {
		for _, pfx := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
			got := routeIfIndex(pfx)
			if got != tunIfIdx {
				log.Printf("fulltun: ПРОВЕРКА ПРОВАЛЕНА: %s стоит на ifIndex %d, а нужен TUN %d — снимаю маршруты (fail-closed), интернет пошёл бы МИМО туннеля", pfx, got, tunIfIdx)
				ok = false
			}
		}
	}
	// есть ли IPv6-дефолт: v4-туннель его не захватывает — честное предупреждение
	if out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"(Get-NetRoute -DestinationPrefix '::/0' -ErrorAction SilentlyContinue | Measure-Object).Count").Output(); err == nil {
		if c := strings.TrimSpace(string(out)); c != "0" && c != "" {
			log.Printf("fulltun: ВНИМАНИЕ: у тебя есть IPv6-дефолт — v6-трафик пойдёт мимо туннеля напрямую (ограничение v4-туннеля; если что-то поломается — скажи, добавим нейтрализацию)")
		}
	}
	if !ok {
		del()
		log.Printf("fulltun: маршруты НЕ встали корректно — сняты. Туннель работает только для 10.99.0.0/24; интернет идёт напрямую. Это честный fail-closed, а не рабочий VPN")
		return noop
	}
	log.Printf("fulltun: маршруты встали и проверены на ifIndex %d (весь v4-трафик в туннель; откат — по Ctrl+C)", tunIfIdx)
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

// ifIndexByIP — ifIndex интерфейса, которому назначен данный IPv4-адрес.
func ifIndexByIP(ip string) int {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"(Get-NetIPAddress -IPAddress '"+ip+"' -AddressFamily IPv4 -ErrorAction SilentlyContinue).InterfaceIndex").Output()
	if err != nil {
		log.Printf("fulltun: Get-NetIPAddress %s: %v", ip, err)
		return 0
	}
	return firstInt(string(out))
}

// routeIfIndex — ifIndex маршрута с данным префиксом (минимальная метрика).
func routeIfIndex(prefix string) int {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"(Get-NetRoute -DestinationPrefix '"+prefix+"' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1).InterfaceIndex").Output()
	if err != nil {
		return 0
	}
	return firstInt(string(out))
}

// firstInt — первое непустое число из вывода PowerShell.
func firstInt(s string) int {
	for _, ln := range strings.Split(s, "\n") {
		if n, err := strconv.Atoi(strings.TrimSpace(ln)); err == nil && n > 0 {
			return n
		}
	}
	return 0
}

// warnProxy — системный HTTP-прокси уводит трафик приложений мимо туннеля
// (curl/браузер идут в прокси, а не по таблице маршрутов). Молчать об этом
// нельзя: внешний IP не изменится, и это будет выглядеть как поломка VPN.
func warnProxy() {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"$p=Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -ErrorAction SilentlyContinue; "+
			"if($p.ProxyEnable -eq 1){$p.ProxyServer}").Output()
	if err == nil {
		if s := strings.TrimSpace(string(out)); s != "" {
			log.Printf("fulltun: ВНИМАНИЕ: включён системный HTTP-прокси %q — приложения пойдут в прокси МИМО туннеля, внешний IP не изменится. Отключи прокси на время проверки", s)
		}
	}
	for _, ev := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"} {
		if v := strings.TrimSpace(os.Getenv(ev)); v != "" {
			log.Printf("fulltun: ВНИМАНИЕ: переменная окружения %s=%q — curl и часть приложений пойдут в прокси МИМО туннеля", ev, v)
		}
	}
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
