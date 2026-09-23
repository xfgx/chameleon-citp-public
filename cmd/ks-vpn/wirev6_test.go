package main

// wirev6_test.go — клиентский v6-провод: случайный свободный порт, случайные
// цели из пула, случайные ИСХОДНЫЕ адреса на каждый пакет, откат по
// ошибкам отправки И по МОЛЧАНИЮ приёма, честные отказы конструктора.

import (
	"net"
	"testing"
	"time"
)

func TestWireV6BindRandomFreePort(t *testing.T) {
	datch := make(chan inPkt, 4)
	w, err := newWireV6("fd6c:2a03:5b4a::/48", 51820, 0, datch, nil)
	if err != nil {
		t.Fatalf("newWireV6: %v", err)
	}
	defer w.close()
	s1 := w.cur.Load().(*net.UDPConn).LocalAddr().(*net.UDPAddr).Port
	if s1 == 0 {
		t.Fatal("порт не назначен")
	}
	if err := w.rebind(); err != nil {
		t.Fatalf("rebind: %v", err)
	}
	s2 := w.cur.Load().(*net.UDPConn).LocalAddr().(*net.UDPAddr).Port
	if s2 == 0 || s2 == s1 {
		t.Fatalf("пересадка порта не дала новый свободный: %d -> %d", s1, s2)
	}
}

func TestWireV6DstRandomFromPool(t *testing.T) {
	datch := make(chan inPkt, 4)
	w, err := newWireV6("2001:db8:2::/48", 51820, 0, datch, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer w.close()
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		d, err := w.nextDst()
		if err != nil {
			t.Fatal(err)
		}
		if d.Port != 51820 {
			t.Fatalf("порт цели %d != 51820", d.Port)
		}
		if !w.pool.Contains(d.IP) {
			t.Fatalf("цель %s вне пула", d.IP)
		}
		seen[d.IP.String()] = true
	}
	if len(seen) < 190 {
		t.Fatalf("подозрительно мало уникальных целей: %d из 200", len(seen))
	}
}

func TestWireV6FallbackOnSendErrors(t *testing.T) {
	datch := make(chan inPkt, 4)
	w, err := newWireV6("2001:db8:ffff::/48", 51820, 0, datch, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer w.close()
	// детерминированный отказ, не зависящий от маршрутизации хоста: закрытый
	// сокет — WriteToUDP всегда ошибается ("use of closed network connection").
	w.cur.Load().(*net.UDPConn).Close()
	for i := 0; i < wireFailsToFallback; i++ {
		_ = w.send([]byte("probe"))
	}
	if w.ok.Load() {
		t.Fatal("после серии ошибок отправки провод обязан уйти в откат")
	}
	if err := w.send([]byte("x")); err != errWire6Down {
		t.Fatalf("в откате send обязан возвращать errWire6Down, got %v", err)
	}
	// проба на живом сокете уходит, НО сама по себе провод В СТРОЙ НЕ
	// возвращает: успешная отправка ничего не доказывает (урок полевого
	// прогона: ~1300 «успешных» отправок и ни одной принятой нодой).
	if err := w.rebind(); err != nil {
		t.Fatal(err)
	}
	if !w.probe([]byte("x")) {
		t.Fatal("проба на живом сокете обязана уйти без ошибки")
	}
	if w.ok.Load() {
		t.Fatal("успешная отправка НЕ должна возвращать провод в строй")
	}
	// в строй возвращает только ФАКТ приёма.
	w.onRx()
	if !w.ok.Load() {
		t.Fatal("после реального приёма провод обязан вернуться в строй")
	}
}

// TestWireV6SilenceFallback — главный урок полевого прогона 2026-09-04:
// отправки успешны, ответов нет — такой провод обязан упасть в откат.
func TestWireV6SilenceFallback(t *testing.T) {
	datch := make(chan inPkt, 4)
	w, err := newWireV6("2001:db8:ffff::/48", 51820, 0, datch, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer w.close()
	now := time.Now().Unix()
	// мало отправок — тишина ничего не доказывает (простой канал).
	w.sentSince.Store(wire6MinSentToTrip - 1)
	w.lastRx.Store(now - wire6SilenceSec - 10)
	w.tick(now)
	if !w.ok.Load() {
		t.Fatal("при простое канала отката быть не должно")
	}
	// реально шлём, ответов нет дольше окна — откат.
	w.sentSince.Store(wire6MinSentToTrip)
	w.tick(now)
	if w.ok.Load() {
		t.Fatal("молчаливая чёрная дыра обязана давать откат на v4")
	}
	// раньше срока перепробы — остаёмся в откате.
	w.tick(now + wire6RetryDownSec - 1)
	if w.ok.Load() {
		t.Fatal("перепроба раньше срока недопустима")
	}
	// по истечении — одна перепроба со свежим окном.
	w.tick(now + wire6RetryDownSec)
	if !w.ok.Load() {
		t.Fatal("после выдержки провод обязан перепробоваться")
	}
}

func TestWireV6RejectsBadPool(t *testing.T) {
	datch := make(chan inPkt, 1)
	if _, err := newWireV6("10.0.0.0/24", 51820, 0, datch, nil); err == nil {
		t.Fatal("IPv4-пул должен отклоняться")
	}
	if _, err := newWireV6("мусор", 51820, 0, datch, nil); err == nil {
		t.Fatal("мусор должен отклоняться")
	}
}

// TestLoopGuardDrop — петлестоп оба плеча: пакеты к проводному IP ноды
// (v4) и к пулу v6-провода (v6) в туннель не входят; прочие — входят.
func TestLoopGuardDrop(t *testing.T) {
	peer := net.ParseIP("192.0.2.10").To4()
	_, pool, err := net.ParseCIDR("2001:db8:2::/48")
	if err != nil {
		t.Fatal(err)
	}
	v4 := func(dst string) []byte {
		p := make([]byte, 20)
		p[0] = 0x45
		copy(p[16:20], net.ParseIP(dst).To4())
		return p
	}
	v6 := func(dst string) []byte {
		p := make([]byte, 40)
		p[0] = 0x60
		copy(p[24:40], net.ParseIP(dst).To16())
		return p
	}
	if !loopGuardDrop(v4("192.0.2.10"), peer, pool) {
		t.Fatal("v4-пакет к проводному IP ноды обязан отбрасываться")
	}
	if loopGuardDrop(v4("1.1.1.1"), peer, pool) {
		t.Fatal("обычный v4-пакет отбрасывать нельзя")
	}
	if !loopGuardDrop(v6("2001:db8:2:dead::1"), peer, pool) {
		t.Fatal("v6-пакет к пулу провода обязан отбрасываться (иначе петля)")
	}
	if loopGuardDrop(v6("2001:4860:4860::8888"), peer, pool) {
		t.Fatal("обычный v6-пакет отбрасывать нельзя")
	}
	if loopGuardDrop(v6("2001:db8:2::1"), peer, nil) {
		t.Fatal("без пула провода v6-плечо молчит")
	}
}
