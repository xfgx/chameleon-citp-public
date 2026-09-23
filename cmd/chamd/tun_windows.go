//go:build windows

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/engine"
)

// TUN-режим: автоподхват всего TCP-трафика Windows 11.
//
// Пакетный путь построен на проверенном стеке tun2socks (gVisor netstack +
// Wintun), а не на самописном клее: адаптер → netstack → наш локальный
// SOCKS5 (127.0.0.1:1080) → сеанс "Хамелеон" → нода → интернет.
//
//  1. Адаптер Wintun "ChameleonVPN" создаётся движком tun2socks.
//  2. Маршруты 0.0.0.0/1 + 128.0.0.0/1 через TUN забирают публичный IPv4.
//  3. Обходы: IP нод и частные сети — напрямую (иначе петля).
//  4. DNS адаптера = 127.0.0.1, где chamd отвечает через туннель.
//  5. QUIC (UDP/443) блокируется файрволом → браузеры сразу идут по TCP.
//
// Требует запуска chamd от администратора.

const (
	tunName = "ChameleonVPN"
	tunIP   = "10.66.0.2"
	tunGW   = "10.66.0.1"
)

type TunDevice struct {
	m *Manager

	mu       sync.Mutex
	running  bool
	bypasses []string // /32 нод (иначе туннель завернёт сам себя)
	coverIPs []string // /32 cover-целей: легенда идёт НАПРЯМУЮ, мимо туннеля
	socks    string   // наш локальный SOCKS5 — пункт назначения движка
}

func NewTun(m *Manager) *TunDevice { return &TunDevice{m: m} }

func (t *TunDevice) SetSocks(addr string) { t.socks = addr }

// AddCoverBypass добавляет host-route /32 для cover-цели через физический
// шлюз — запросы легендирования идут мимо туннеля и видны провайдеру как
// обычный фоновый HTTPS к RU-сервисам. Безопасно звать до/во время/после
// поднятия TUN: маршрут применяется при старте или сразу, если TUN активен.
func (t *TunDevice) AddCoverBypass(ip string) {
	t.mu.Lock()
	for _, e := range t.coverIPs {
		if e == ip {
			t.mu.Unlock()
			return
		}
	}
	t.coverIPs = append(t.coverIPs, ip)
	running := t.running
	t.mu.Unlock()
	if running {
		if gw, err := defaultGateway(); err == nil {
			if err := run("route", "add", ip, "mask", "255.255.255.255", gw, "metric", "5"); err != nil {
				t.m.logf("tun: обход cover %s не добавлен: %v", ip, err)
			}
		}
	}
}

func run(name string, args ...string) error {
	_, err := runOut(name, args...)
	return err
}

func runOut(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s %s: %v (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

// RunTunProbe — режим пробы: создать адаптер Wintun и выйти.
// Вызывается в отдельном процессе, потому что engine.Start() при ошибке
// делает log.Fatal — в основном процессе это убило бы демон.
func RunTunProbe() {
	engine.Insert(&engine.Key{Device: "tun://" + tunName, Proxy: "socks5://127.0.0.1:9", LogLevel: "error"})
	engine.Start() // при ошибке — fatal (умрёт только этот процесс-проба)
	engine.Stop()
	os.Exit(0)
}

// preflightAdapter запускает себя же с -tun-probe: адаптер создаётся
// (или переиспользуется) без риска уронить основной процесс.
func (t *TunDevice) preflightAdapter() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, "-tun-probe")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("probe: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// cleanWintun удаляет осиротевшие Wintun-адаптеры и сам пакет драйвера
// из хранилища — после этого tun2socks ставит драйвер заново, чистый.
func cleanWintun() {
	_ = run("powershell", "-NoProfile", "-Command",
		`Get-NetAdapter -InterfaceDescription "Wintun*" -IncludeHidden -ErrorAction SilentlyContinue | Remove-NetAdapter -Confirm:$false -ErrorAction SilentlyContinue`)
	_ = run("powershell", "-NoProfile", "-Command",
		`$out = pnputil /enum-drivers | Out-String; `+
			`$blocks = $out -split "`+"`r?`n`r?`n"+`"; `+
			`foreach ($b in $blocks) { if ($b -match '(?i)wintun' -and $b -match '(oem\d+\.inf)') { pnputil /delete-driver $Matches[1] /uninstall /force } }`)
}

// Start поднимает движок, IP-адрес, DNS и маршруты. Идемпотентен.
func (t *TunDevice) Start() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.running {
		return nil
	}

	// engine.Start() при ошибке завершает весь процесс (fatal). Поэтому
	// сначала префлайт: адаптер создаётся в ОТДЕЛЬНОМ процессе-пробе.
	// Если проба падает (битый драйвер Wintun после прошлых крашей) —
	// чистим драйвер и осиротевшие адаптеры, пробуем ещё раз.
	if err := run("net", "session"); err != nil {
		return fmt.Errorf("TUN требует запуска от администратора — перезапустите chamd с правами admin, работаем через SOCKS5")
	}
	if err := t.preflightAdapter(); err != nil {
		log.Printf("tun: префлайт адаптера: %v — чищу драйвер Wintun", err)
		t.m.logf("tun: адаптер не создался (%v), чищу драйвер Wintun...", err)
		cleanWintun()
		if err := t.preflightAdapter(); err != nil {
			return fmt.Errorf("адаптер Wintun не создаётся даже после чистки драйвера: %v — работаем через SOCKS5", err)
		}
	}

	key := &engine.Key{
		Device:   "tun://" + tunName,
		Proxy:    "socks5://" + t.socks,
		LogLevel: "info", // диагностика: видим каждый TCP-поток в консоли
		// Скорость: ручные буферы TCP под туннельный RTT и модерация
		// receive window — иначе gVisor душит поток дефолтами.
		MTU:                      1500,
		TCPModerateReceiveBuffer: true,
		TCPSendBufferSize:        "4MB",
		TCPReceiveBufferSize:     "4MB",
	}
	engine.Insert(key)
	engine.Start()

	// Ждём появления адаптера (создание занимает пару секунд).
	var ifIdx string
	for i := 0; i < 20; i++ {
		if idx, err := tunIfIndex(); err == nil {
			ifIdx = idx
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if ifIdx == "" {
		engine.Stop()
		return fmt.Errorf("адаптер %s не появился (нужны права администратора)", tunName)
	}

	if err := run("netsh", "interface", "ip", "set", "address", "name="+tunName, "static", tunIP, "255.255.255.0"); err != nil {
		engine.Stop()
		return fmt.Errorf("адрес адаптера: %w", err)
	}
	// DNS адаптера → локальный резолвер chamd (ходит через туннель).
	_ = run("netsh", "interface", "ipv4", "set", "dnsservers", "name="+tunName, "static", "127.0.0.1", "primary")

	// КЛЮЧЕВОЕ для Windows 11: отключаем аппаратные оффлоады адаптера.
	// Иначе Windows шлёт в TUN пакеты с нулевыми контрольными суммами и
	// гигантскими LSO-сегментами — userspace-стек их молча дропает,
	// TLS-хендшейк замирает на середине и браузер даёт SSL-ошибку.
	// ВАЖНО: привязка по InterfaceIndex — NetAdapter-имя адаптера Wintun
	// часто НЕ совпадает с tunName ("ChameleonVPN 1", "Local Area Connection* N").
	ps := `$a = Get-NetAdapter -InterfaceIndex ` + ifIdx + ` -ErrorAction SilentlyContinue; ` +
		`if (-not $a) { $a = Get-NetAdapter -InterfaceDescription "Wintun*" -ErrorAction SilentlyContinue | Select-Object -First 1 }; ` +
		`if ($a) { $a | Disable-NetAdapterChecksumOffload -TcpIPv4 -UdpIPv4 -Confirm:$false -ErrorAction SilentlyContinue; ` +
		`$a | Disable-NetAdapterLso -IPv4 -Confirm:$false -ErrorAction SilentlyContinue; ` +
		`$a | Disable-NetAdapterRsc -IPv4 -Confirm:$false -ErrorAction SilentlyContinue; "offload off: " + $a.Name } else { "адаптер не найден" }`
	if out, err := runOut("powershell", "-NoProfile", "-Command", ps); err != nil {
		t.m.logf("tun: offload не отключился: %v", err)
		log.Printf("tun: offload warning: %v", err)
	} else {
		log.Printf("tun: %s", out)
	}

	// QUIC теперь туннелируется (UDP-релей), старый блок не нужен.
	_ = run("netsh", "advfirewall", "firewall", "delete", "rule", "name=ChameleonBlockQUIC")

	if err := t.setupRoutes(ifIdx); err != nil {
		t.removeRoutes()
		engine.Stop()
		return fmt.Errorf("маршруты TUN: %w", err)
	}

	t.running = true
	// Самопроверка: маршруты захвата реально на месте?
	out, _ := exec.Command("route", "print", "-4", "0.0.0.0").Output()
	if strings.Contains(string(out), "128.0.0.0") {
		log.Printf("tun: ПРОВЕРКА OK — маршрут 0.0.0.0/1 присутствует в таблице")
	} else {
		log.Printf("tun: ПРОВЕРКА ПРОВАЛЕНА — маршрута 0.0.0.0/1 НЕТ в таблице!")
	}
	t.m.logf("tun: адаптер %s поднят (%s, if %s), весь TCP идёт через туннель", tunName, tunIP, ifIdx)
	log.Printf("tun: адаптер %s поднят, маршруты активны — весь TCP через туннель", tunName)
	return nil
}

// setupRoutes перенаправляет публичный IPv4 в TUN, оставляя обходы.
func (t *TunDevice) setupRoutes(ifIdx string) error {
	gw, err := defaultGateway()
	if err != nil {
		return err
	}
	// Обходы: частные сети + IP всех нод из пула (иначе туннель завернёт
	// собственное соединение с нодой внутрь себя).
	bypass := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	t.bypasses = nil
	for _, s := range t.m.store.List() {
		host, _, err := net.SplitHostPort(s.Addr)
		if err != nil {
			continue
		}
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			continue
		}
		bypass = append(bypass, ips[0].String()+"/32")
		t.bypasses = append(t.bypasses, ips[0].String())
	}
	for _, cidr := range bypass {
		ip, mask := splitCIDR(cidr)
		if err := run("route", "add", ip, "mask", mask, gw, "metric", "5"); err != nil {
			t.m.logf("tun: обход %s не добавлен: %v", cidr, err)
		}
	}
	// Обходы cover-целей: легендированный трафик идёт напрямую, иначе
	// он попадёт внутрь собственного туннеля и легенда бессмысленна.
	for _, ip := range t.coverIPs {
		if err := run("route", "add", ip, "mask", "255.255.255.255", gw, "metric", "5"); err != nil {
			t.m.logf("tun: обход cover %s не добавлен: %v", ip, err)
		}
	}
	// Захват: два /1 покрывают весь IPv4 и специфичнее default route.
	if err := run("route", "add", "0.0.0.0", "mask", "128.0.0.0", tunGW, "metric", "1", "if", ifIdx); err != nil {
		return err
	}
	if err := run("route", "add", "128.0.0.0", "mask", "128.0.0.0", tunGW, "metric", "1", "if", ifIdx); err != nil {
		return err
	}
	t.m.logf("tun: маршруты 0.0.0.0/1 и 128.0.0.0/1 → %s (if %s), обходов: %d", tunGW, ifIdx, len(bypass))
	return nil
}

// tunIfIndex — индекс адаптера ChameleonVPN из netsh.
func tunIfIndex() (string, error) {
	out, err := exec.Command("netsh", "interface", "ipv4", "show", "interfaces").Output()
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, tunName) {
			f := strings.Fields(line)
			if len(f) >= 1 {
				return f[0], nil
			}
		}
	}
	return "", fmt.Errorf("интерфейс %s не найден", tunName)
}

func (t *TunDevice) removeRoutes() {
	gw, err := defaultGateway()
	_ = run("route", "delete", "0.0.0.0", "mask", "128.0.0.0", tunGW)
	_ = run("route", "delete", "128.0.0.0", "mask", "128.0.0.0", tunGW)
	if err == nil {
		for _, ip := range t.bypasses {
			_ = run("route", "delete", ip, "mask", "255.255.255.255", gw)
		}
		for _, ip := range t.coverIPs {
			_ = run("route", "delete", ip, "mask", "255.255.255.255", gw)
		}
	}
}

func splitCIDR(cidr string) (string, string) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return cidr, "255.255.255.255"
	}
	return ip.String(), net.IP(ipnet.Mask).String()
}

// defaultGateway находит шлюз текущего default route через `route print`.
func defaultGateway() (string, error) {
	out, err := exec.Command("route", "print", "-4", "0.0.0.0").Output()
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == "0.0.0.0" && f[1] == "0.0.0.0" {
			return f[2], nil
		}
	}
	return "", fmt.Errorf("default gateway не найден")
}

// Stop гасит TUN и возвращает маршруты.
func (t *TunDevice) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.running {
		return
	}
	t.running = false
	t.removeRoutes()
	_ = run("netsh", "advfirewall", "firewall", "delete", "rule", "name=ChameleonBlockQUIC")
	engine.Stop()
	t.m.logf("tun: адаптер остановлен, маршруты восстановлены")
	log.Printf("tun: остановлен, маршруты восстановлены")
}
