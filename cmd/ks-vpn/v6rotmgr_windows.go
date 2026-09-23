//go:build windows

package main

// v6rotmgr_windows.go — применение адресов пула на Windows-клиенте.
//
// Адреса добавляются как /128 (без on-link семантики /48: иначе весь пул
// стал бы «локальным» и запросы к адресам узлов туннеля ушли бы в наш же
// TUN). Предпочтительный источник — через SkipAsSource: новый адрес false,
// прежние true (новые потоки берут новый адрес; старые потоки доживают).
// ::/0 заводится в туннель на время работы; пост-проверка как в fulltun v3:
// маршрут не встал — честный отказ, ничего не оставляем наполовину.
// Всё в ActiveStore: после выхода/reboot не остаётся хвостов.

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
)

type v6mgrWin struct {
	ifname     string
	added      []string // история адресов пула (для demote/prune/отката)
	wirePinned []string // запиненные мимо туннеля префиксы провода
}

func newV6AddrMgr(ifname string) v6AddrMgr { return &v6mgrWin{ifname: ifname} }

// ps — один PowerShell-вызов (локаль-независимо, как в fulltun_windows.go).
func (m *v6mgrWin) ps(script string) (string, error) {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive",
		"-Command", script).CombinedOutput()
	return string(out), err
}

func (m *v6mgrWin) Setup() (func(), error) {
	// тихий адаптер: без RA/DHCPv6-шума
	exec.Command("netsh", "interface", "ipv6", "set", "interface", m.ifname,
		"routerdiscovery=disabled", "advertise=disabled", "managedaddress=disabled",
		"otherstateful=disabled").Run()
	// MTU v6 как у v4-стека (1300): пакет целиком в одну KS-датаграмму
	if out, err := exec.Command("netsh", "interface", "ipv6", "set", "subinterface",
		m.ifname, "mtu=1300", "store=active").CombinedOutput(); err != nil {
		log.Printf("v6rot: mtu 1300 (ipv6) на %s: %v (%s)", m.ifname, err, strings.TrimSpace(string(out)))
	}
	// зачистка хвостов прошлых запусков: наш ::/0 и ручные v6-адреса адаптера
	m.ps(fmt.Sprintf("Remove-NetRoute -DestinationPrefix '::/0' -InterfaceAlias '%s' -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue", m.ifname))
	m.ps(fmt.Sprintf("Get-NetIPAddress -InterfaceAlias '%s' -AddressFamily IPv6 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object {$_.PrefixOrigin -eq 'Manual'} | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue", m.ifname))
	m.added = nil
	// дефолт в туннель + пост-проверка (fail-closed, как fulltun v3)
	if out, err := m.ps(fmt.Sprintf("New-NetRoute -DestinationPrefix '::/0' -InterfaceAlias '%s' -PolicyStore ActiveStore -ErrorAction Stop | Out-Null", m.ifname)); err != nil {
		return nil, fmt.Errorf("v6rot: ::/0 в туннель не встал: %v (%s) — v6 выключен, v4 не тронут", err, strings.TrimSpace(out))
	}
	out, _ := m.ps(fmt.Sprintf("(Get-NetRoute -DestinationPrefix '::/0' -InterfaceAlias '%s' -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Measure-Object).Count", m.ifname))
	if c := strings.TrimSpace(out); c == "" || c == "0" {
		m.ps(fmt.Sprintf("Remove-NetRoute -DestinationPrefix '::/0' -InterfaceAlias '%s' -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue", m.ifname))
		return nil, fmt.Errorf("v6rot: ::/0 не подтвердился пост-проверкой — v6 выключен, v4 не тронут")
	}
	log.Printf("v6rot: ::/0 -> %s (пост-проверка OK; откат по Ctrl+C)", m.ifname)
	return func() {
		m.ps(fmt.Sprintf("Remove-NetRoute -DestinationPrefix '::/0' -InterfaceAlias '%s' -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue", m.ifname))
		for _, p := range m.wirePinned {
			m.ps(fmt.Sprintf("Remove-NetRoute -DestinationPrefix '%s' -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue", p))
		}
		m.Prune(0)
		log.Printf("v6rot: маршрут, пины и адреса пула сняты")
	}, nil
}

func (m *v6mgrWin) Add(ip net.IP) error {
	a := ip.String()
	if out, err := m.ps(fmt.Sprintf("New-NetIPAddress -InterfaceAlias '%s' -IPAddress '%s' -PrefixLength 128 -PolicyStore ActiveStore -SkipAsSource:$false -ErrorAction Stop | Out-Null", m.ifname, a)); err != nil {
		return fmt.Errorf("add %s: %v (%s)", a, err, strings.TrimSpace(out))
	}
	if len(m.added) > 0 {
		m.ps(fmt.Sprintf("Get-NetIPAddress -InterfaceAlias '%s' -AddressFamily IPv6 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object {@('%s') -contains $_.IPAddress} | Set-NetIPAddress -SkipAsSource:$true -ErrorAction SilentlyContinue", m.ifname, strings.Join(m.added, "','")))
	}
	m.added = append(m.added, a)
	return nil
}

// PinWirePool — пул v6-провода ноды (напр. 2001:db8:2::/48) пингуется на
// НАТИВНЫЙ v6-дефолт (шлюз+интерфейс существующего ::/0, исключая наш TUN):
// туннельный ::/0 ротации перекрывается более специфичным /48 на физический
// путь — иначе датаграммы провода ушли бы в наш же TUN (петля). Нет нативного
// v6 — честная ошибка (wirev6 сам уйдёт в откат по ошибкам отправки).
func (m *v6mgrWin) PinWirePool(prefix *net.IPNet) error {
	q := fmt.Sprintf(`$t='%s'; $p='%s'
Get-NetRoute -DestinationPrefix $p -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Remove-NetRoute -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue
$n=Get-NetRoute -DestinationPrefix '::/0' -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object {$_.InterfaceAlias -ne $t -and $_.NextHop -ne '::'} | Sort-Object RouteMetric | Select-Object -First 1
if(-not $n){ $d=@(); Get-NetRoute -DestinationPrefix '::/0' -PolicyStore ActiveStore -ErrorAction SilentlyContinue | ForEach-Object { $d += "cand ::/0 if=$($_.InterfaceAlias) nh=$($_.NextHop) metric=$($_.RouteMetric)" }; ($d -join [char]10); exit 3 }
New-NetRoute -DestinationPrefix $p -NextHop $n.NextHop -InterfaceIndex $n.InterfaceIndex -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
$g=Get-NetRoute -DestinationPrefix $p -PolicyStore ActiveStore -ErrorAction SilentlyContinue
if(-not $g){ exit 5 }
if($g | Where-Object {$_.InterfaceAlias -eq $t}){ exit 6 }
"PIN|$(($g | Select-Object -First 1).InterfaceAlias)|$($n.NextHop)"`, m.ifname, prefix.String())
	out, err := m.ps(q)
	text := strings.TrimSpace(out)
	if err != nil || !strings.Contains(text, "PIN|") {
		return fmt.Errorf("%v (%s)", err, text)
	}
	via := text
	for _, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "PIN|") {
			via = strings.TrimSpace(l)
			break
		}
	}
	f := strings.Split(via, "|")
	m.wirePinned = append(m.wirePinned, prefix.String())
	if len(f) >= 3 {
		log.Printf("v6rot: пул провода %s запинен мимо туннеля: через %s, шлюз %s (подтверждено пост-проверкой)", prefix, f[1], f[2])
	} else {
		log.Printf("v6rot: пул провода %s запинен мимо туннеля (подтверждено пост-проверкой)", prefix)
	}
	return nil
}

func (m *v6mgrWin) Prune(keep int) error {
	for len(m.added) > keep {
		old := m.added[0]
		m.added = m.added[1:]
		m.ps(fmt.Sprintf("Remove-NetIPAddress -InterfaceAlias '%s' -IPAddress '%s' -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue", m.ifname, old))
	}
	return nil
}
