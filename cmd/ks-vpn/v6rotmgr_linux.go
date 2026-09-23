//go:build linux

package main

// v6rotmgr_linux.go — применение адресов пула на Linux-клиенте.
// Боевая роль клиента — Windows; Linux-вариант нужен для прогонов в netns
// на RU-ноде и для linux-хостов владельца. Аналог SkipAsSource здесь —
// preferred_lft=0 у прежних адресов (deprecated-адрес не выбирается источником
// новых потоков, но продолжает принимать ответы существующих).
// Маршруты Setup не трогает: их ставит обвязка стенда/хоста.

import (
	"net"
	"os/exec"
	"strings"
)

type v6mgrLin struct {
	ifname string
	added  []string
}

func newV6AddrMgr(ifname string) v6AddrMgr { return &v6mgrLin{ifname: ifname} }

func (m *v6mgrLin) run(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil && strings.Contains(string(out), "File exists") {
		return nil // идемпотентность повтора
	}
	return err
}

func (m *v6mgrLin) Setup() (func(), error) {
	return func() { m.Prune(0) }, nil
}

func (m *v6mgrLin) Add(ip net.IP) error {
	a := ip.String()
	if err := m.run("-6", "addr", "add", a+"/128", "dev", m.ifname); err != nil {
		return err
	}
	for _, old := range m.added {
		m.run("-6", "addr", "change", old+"/128", "dev", m.ifname, "preferred_lft", "0")
	}
	m.added = append(m.added, a)
	return nil
}

// PinWirePool — на Linux no-op: маршрут пула провода ставит обвязка
// (стенд .tools/ks/ks_v6wire_test.sh; на хостах — сетап владельца).
func (m *v6mgrLin) PinWirePool(prefix *net.IPNet) error { return nil }

func (m *v6mgrLin) Prune(keep int) error {
	for len(m.added) > keep {
		old := m.added[0]
		m.added = m.added[1:]
		m.run("-6", "addr", "del", old+"/128", "dev", m.ifname)
	}
	return nil
}
