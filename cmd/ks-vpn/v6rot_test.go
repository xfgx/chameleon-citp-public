package main

// v6rot_test.go — генератор адресов пула: маскирование по префиксу,
// исключения (адрес сети, нижний /64), покрытие хостовых бит, отказы.

import (
	"net"
	"testing"
)

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// Каждый вытянутый адрес обязан лежать в префиксе и не попадать в нижний
// /64 (там адреса узлов 6in4), не быть адресом сети.
func TestRandV6WithinPrefix(t *testing.T) {
	p := mustCIDR(t, "2001:db8:1::/48")
	seen := map[string]bool{}
	for i := 0; i < 5000; i++ {
		ip, err := randV6(p)
		if err != nil {
			t.Fatalf("вытягивание %d: %v", i, err)
		}
		if !p.Contains(ip) {
			t.Fatalf("адрес %s вне префикса %s", ip, p)
		}
		if ip.Equal(p.IP) {
			t.Fatal("вытянут адрес сети (subnet-router anycast)")
		}
		if string(ip[:8]) == string(p.IP.To16()[:8]) {
			t.Fatalf("адрес %s попал в нижний /64 (узлы туннеля)", ip)
		}
		seen[ip.String()] = true
	}
	if len(seen) < 4990 {
		t.Fatalf("подозрительно много коллизий: %d уникальных из 5000", len(seen))
	}
}

// Хостовые биты реально перемешиваются: у /48 это 80 бит (subnet+IID).
func TestRandV6HostBitsVary(t *testing.T) {
	p := mustCIDR(t, "2001:db8:1::/48")
	var subnetBits, iidBits uint64
	for i := 0; i < 200; i++ {
		ip, err := randV6(p)
		if err != nil {
			t.Fatal(err)
		}
		b := ip.To16()
		subnetBits |= uint64(b[6])<<8 | uint64(b[7])
		for _, x := range b[8:] {
			iidBits |= uint64(x)
		}
	}
	if subnetBits == 0 {
		t.Fatal("subnet-поле (биты 48..63) не перемешивается")
	}
	if iidBits == 0 {
		t.Fatal("IID (биты 64..127) не перемешивается")
	}
}

// Для префиксов /64 и уже исключение нижнего /64 не применяется (иначе
// генерация была бы невозможна); /120 — без исключений, кроме адреса сети.
func TestRandV6NarrowPrefixes(t *testing.T) {
	p64 := mustCIDR(t, "fd6b:6b73:5b49:1::/64")
	for i := 0; i < 100; i++ {
		ip, err := randV6(p64)
		if err != nil {
			t.Fatal(err)
		}
		if !p64.Contains(ip) || ip.Equal(p64.IP) {
			t.Fatalf("/64: плохой адрес %s", ip)
		}
	}
	p120 := mustCIDR(t, "fd6b:6b73:5b49:1::aaaa:bb00/120")
	for i := 0; i < 100; i++ {
		ip, err := randV6(p120)
		if err != nil {
			t.Fatal(err)
		}
		if !p120.Contains(ip) || ip.Equal(p120.IP) {
			t.Fatalf("/120: плохой адрес %s", ip)
		}
	}
}

// Честные отказы конструктора и генератора.
func TestV6RotatorRejectsBadInput(t *testing.T) {
	if _, err := newV6Rotator("10.0.0.0/24", "ks0", 5); err == nil {
		t.Fatal("IPv4-префикс должен отклоняться")
	}
	if _, err := newV6Rotator("2001:db8:1::1/128", "ks0", 5); err == nil {
		t.Fatal("/128 должен отклоняться (нечего ротировать)")
	}
	if _, err := newV6Rotator("не-префикс", "ks0", 5); err == nil {
		t.Fatal("мусор должен отклоняться")
	}
	if _, err := randV6(mustCIDR(t, "2001:db8:1::1/128")); err == nil {
		t.Fatal("randV6 на /128 должен отказывать")
	}
	// зажим периода
	r, err := newV6Rotator("2001:db8:1::/48", "ks0", 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.period < 1e9 {
		t.Fatalf("период не зажат до 1с: %s", r.period)
	}
}
