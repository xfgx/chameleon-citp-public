//go:build windows

package main

// wiresrc6_windows.go — исходные адреса провода на Windows.
//
// Адреса назначаются на НАТИВНЫЙ адаптер (тот, у которого есть глобальный
// v6-адрес от провайдера, НЕ наш TUN) как /128 с SkipAsSource:$true:
// обычный трафик системы их не выбирает, а наш явный bind — работает.
// Всё в ActiveStore: после выхода/reboot хвостов не остаётся.
//
// DAD: свеженазначенный адрес некоторое время Tentative и bind на него падает
// (WSAEADDRNOTAVAIL) — поэтому bind с короткими повторами до 3с.
//
// Урок поля 2026-09-04: прежний Detect искал адрес ТОЛЬКО на интерфейсе
// нативного ::/0 и ТОЛЬКО с PrefixOrigin RouterAdvertisement/Dhcp. На живой
// машине это дало exit 4 и молчание о причине. Теперь: перебор всех
// не-TUN интерфейсов, глобальный юникаст 2000::/3, предпочтение RA/DHCPv6,
// а при отказе — честный дамп того, что видно (адреса, origin, ::/0-маршруты).

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type srcMgrWin struct {
	ifIndex int
	ifAlias string
}

func newSrcMgr6() srcMgr6 { return &srcMgrWin{} }

func (m *srcMgrWin) ps(script string) (string, error) {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive",
		"-Command", script).CombinedOutput()
	return string(out), err
}

// diagQuery — что реально видно в стеке (для честного лога при отказе).
const diagQuery = `$t='%s'
$d=@()
$ips = Get-NetIPAddress -AddressFamily IPv6 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -ne $t -and $_.IPAddress -match '^[23]' -and $_.IPAddress -notlike 'fe80*' }
foreach($a in $ips){ $d += "addr $($a.IPAddress)/$($a.PrefixLength) if=$($a.InterfaceAlias) origin=$($a.PrefixOrigin)/$($a.SuffixOrigin) state=$($a.AddressState)" }
foreach($r in (Get-NetRoute -DestinationPrefix '::/0' -PolicyStore ActiveStore -ErrorAction SilentlyContinue)){ $d += "route ::/0 if=$($r.InterfaceAlias) nh=$($r.NextHop) metric=$($r.RouteMetric)" }
if($d.Count -eq 0){ $d += 'глобальных v6-адресов и ::/0-маршрутов вне туннеля не найдено' }
$pick = $ips | Where-Object {($_.PrefixOrigin -eq 'RouterAdvertisement' -or $_.PrefixOrigin -eq 'Dhcp') -and $_.PrefixLength -lt 128} | Sort-Object PrefixLength | Select-Object -First 1
if(-not $pick){ $pick = $ips | Where-Object {$_.PrefixLength -lt 128} | Sort-Object PrefixLength | Select-Object -First 1 }
if(-not $pick){ $pick = $ips | Select-Object -First 1 }
if($pick){ "PICK|$($pick.IPAddress)|$($pick.PrefixLength)|$($pick.InterfaceIndex)|$($pick.InterfaceAlias)|$($pick.PrefixOrigin)" }
$d -join [char]10`

// Detect — нативный глобальный v6-префикс любого не-TUN интерфейса.
// Возвращает префикс; при отказе — ошибку с дампом наблюдаемого состояния,
// чтобы причина была видна из лога, а не угадывалась.
func (m *srcMgrWin) Detect(tunIfname string) (*net.IPNet, error) {
	out, err := m.ps(fmt.Sprintf(diagQuery, tunIfname))
	text := strings.TrimSpace(out)
	if err != nil && !strings.Contains(text, "PICK|") {
		return nil, fmt.Errorf("%w; стек видит:\n%s", errNoNativeV6, diagTail(text))
	}
	var line string
	for _, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "PICK|") {
			line = strings.TrimSpace(l)
			break
		}
	}
	if line == "" {
		return nil, fmt.Errorf("%w; стек видит:\n%s", errNoNativeV6, diagTail(text))
	}
	f := strings.Split(line, "|")
	if len(f) < 6 {
		return nil, fmt.Errorf("%w; неразборный ответ: %s", errNoNativeV6, line)
	}
	ip := net.ParseIP(strings.TrimSpace(f[1]))
	plen, errLen := strconv.Atoi(strings.TrimSpace(f[2]))
	idx, errIdx := strconv.Atoi(strings.TrimSpace(f[3]))
	if ip == nil || ip.To16() == nil || errLen != nil || errIdx != nil {
		return nil, fmt.Errorf("%w; неразборный ответ: %s", errNoNativeV6, line)
	}
	if plen >= 128 {
		return nil, fmt.Errorf("%w: провайдер выдал только %s/128 на %s — рандомизировать источник нечем",
			errSrcTooNarrow, ip, strings.TrimSpace(f[4]))
	}
	m.ifIndex, m.ifAlias = idx, strings.TrimSpace(f[4])
	log.Printf("wire6src: нативный v6 найден на %s: %s/%d (origin=%s)",
		m.ifAlias, ip, plen, strings.TrimSpace(f[5]))
	mask := net.CIDRMask(plen, 128)
	return &net.IPNet{IP: ip.Mask(mask), Mask: mask}, nil
}

// diagTail — не заливаем лог целиком, но и не прячем суть.
func diagTail(s string) string {
	ls := strings.Split(s, "\n")
	if len(ls) > 12 {
		ls = ls[:12]
	}
	for i := range ls {
		ls[i] = "  " + strings.TrimSpace(ls[i])
	}
	return strings.Join(ls, "\n")
}

// Listen — назначить адрес и привязать к нему UDP-сокет (случайный порт).
func (m *srcMgrWin) Listen(ip net.IP) (*net.UDPConn, error) {
	if m.ifIndex == 0 {
		return nil, errNoNativeV6
	}
	a := ip.String()
	if out, err := m.ps(fmt.Sprintf("New-NetIPAddress -InterfaceIndex %d -IPAddress '%s' -PrefixLength 128 -SkipAsSource:$true -PolicyStore ActiveStore -ErrorAction Stop | Out-Null", m.ifIndex, a)); err != nil {
		return nil, fmt.Errorf("wire6src: назначение %s на %s: %v (%s)", a, m.ifAlias, err, strings.TrimSpace(out))
	}
	// DAD-окно: ждём выхода адреса из Tentative.
	var lastErr error
	for i := 0; i < 15; i++ {
		sock, err := net.ListenUDP("udp6", &net.UDPAddr{IP: ip, Port: 0})
		if err == nil {
			return sock, nil
		}
		lastErr = err
		time.Sleep(200 * time.Millisecond)
	}
	m.Release(ip)
	return nil, fmt.Errorf("wire6src: bind на %s не удался: %v", a, lastErr)
}

func (m *srcMgrWin) Release(ip net.IP) {
	if m.ifIndex == 0 {
		return
	}
	m.ps(fmt.Sprintf("Remove-NetIPAddress -InterfaceIndex %d -IPAddress '%s' -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue", m.ifIndex, ip.String()))
}
