package chameleon

// cf_schedule_runtime_test.go — этап F, вшитый в боевой путь Control Fabric:
//
//   1. Раундтрип сообщения с привязкой к эпохе по всем каналам (board, DNS с
//      эпохальной меткой, CAR со смещением окна кодовой книги);
//   2. Replay сообщения старой эпохи отбрасывается (F3);
//   3. Ротация кодовой книги детерминирована и согласована сторонами (F2);
//   4. Legacy-режим (без WithSchedule) не меняет прежний формат (регрессия).

import (
	"bytes"
	"context"
	"testing"
	"time"
)

// scheduledFabric — фабрика с включённым этапом F (каноническая модель v1).
func scheduledFabric(seed string, cdn *CDNCacheStateChannel, car *CARChannel, dns *DNSBeacon) *ControlFabric {
	return NewControlFabric([]byte(seed), cdn, car, dns, nil).WithSchedule(nil, 0)
}

func TestScheduleCodebookRotation(t *testing.T) {
	book := NewCARCodebook([]byte("rot-seed"), 16)
	if got := book.Rotated(0); got.Label(0) != book.Label(0) {
		t.Fatal("Rotated(0) должен совпадать с исходной книгой")
	}
	r3 := book.Rotated(3)
	if r3.Label(0) != book.Label(3) || r3.Label(13) != book.Label(0) {
		t.Fatal("циклический сдвиг неверен")
	}
	if r3.Windows() != book.Windows() {
		t.Fatal("ротация не должна менять число окон")
	}
	if book.Rotated(16+3).Label(0) != r3.Label(0) {
		t.Fatal("сдвиг обязан быть по модулю числа окон")
	}
	if book.Rotated(-1).Label(0) != book.Label(15) {
		t.Fatal("отрицательный сдвиг обязан нормализоваться")
	}
	// Множество меток неизменно — меняется только порядок старта.
	base := make(map[string]bool)
	for _, l := range book.Labels() {
		base[l] = true
	}
	for _, l := range r3.Labels() {
		if !base[l] {
			t.Fatalf("ротация ввела чужую метку %s", l)
		}
	}
}

func TestScheduleBoardRoundtrip(t *testing.T) {
	ctx := context.Background()
	msg := []byte("next-entry=10.0.0.42:8443")

	cdn := NewCDNCacheStateChannel("127.0.0.1:0")
	go func() { _ = cdn.Serve() }()
	defer func() { _ = cdn.Shutdown() }()
	addr := waitAddr(cdn.Addr)

	node := scheduledFabric("sched-seed", cdn, nil, nil)
	if err := node.PublishControl(ctx, "s1", msg); err != nil {
		t.Fatal(err)
	}
	client := scheduledFabric("sched-seed", nil, nil, nil)
	got, err := client.RecoverControl(ctx, "s1", NewCDNCacheStateClient("http://"+addr))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("board roundtrip: got %q", got)
	}

	// Контроль формата: legacy-читатель (без этапа F) получает сообщение с
	// 8-байтным префиксом эпохи — прозрачно прочитать его он не может
	// (документированная несовместимость, откат только парой нода+клиент).
	legacy := NewControlFabric([]byte("sched-seed"), nil, nil, nil, nil)
	lg, err := legacy.RecoverControl(ctx, "s1", NewCDNCacheStateClient("http://"+addr))
	if err == nil && bytes.Equal(lg, msg) {
		t.Fatal("legacy-читатель не должен прозрачно читать epoch-bound сообщение")
	}
}

func TestScheduleRejectsReplayedOldEpoch(t *testing.T) {
	ctx := context.Background()
	seed := []byte("replay-seed")
	node := scheduledFabric(string(seed), nil, nil, nil)
	key := node.SessionSecret()
	cur := EpochAt(time.Now(), DefaultScheduleEpochLen)

	// Сообщение, привязанное к эпохе далеко в прошлом (replay).
	old := BindEpoch([]byte("next-entry=6.6.6.6:8443"), cur-5)
	enc, err := AEADEncrypt(key, old)
	if err != nil {
		t.Fatal(err)
	}

	cdn := NewCDNCacheStateChannel("127.0.0.1:0")
	go func() { _ = cdn.Serve() }()
	defer func() { _ = cdn.Shutdown() }()
	addr := waitAddr(cdn.Addr)
	cdn.Publish("s1", enc)

	client := scheduledFabric(string(seed), nil, nil, nil)
	if _, err := client.RecoverControl(ctx, "s1", NewCDNCacheStateClient("http://"+addr)); err == nil {
		t.Fatal("replay старой эпохи обязан отбрасываться (F3)")
	}
}

func TestScheduleDNSEpochLabelRoundtrip(t *testing.T) {
	ctx := context.Background()
	msg := []byte("next-entry=10.9.9.9:8443")

	dns := NewDNSBeacon("127.0.0.1:0", "dd.sched.lab", "c", 5)
	go func() { _ = dns.Serve() }()
	defer func() { _ = dns.Close() }()
	daddr := waitAddr(dns.LocalAddr)

	node := scheduledFabric("dns-sched", nil, nil, dns)
	if err := node.PublishControl(ctx, "s1", msg); err != nil {
		t.Fatal(err)
	}

	dh, dp := hostPort(daddr)
	reader := NewDNSBeaconReader(dh, dp, "dd.sched.lab", "c")
	client := scheduledFabric("dns-sched", nil, nil, nil)
	got, via, err := client.RecoverControlAny(ctx, "s1", nil, reader, nil, nil)
	if err != nil || via != "dns" || !bytes.Equal(got, msg) {
		t.Fatalf("dns roundtrip: via=%s got=%q err=%v", via, got, err)
	}
}

func TestScheduleCAROffsetRoundtrip(t *testing.T) {
	ctx := context.Background()
	msg := []byte("flavor=vk-video")

	car := NewCARChannel("127.0.0.1:0")
	go func() { _ = car.Serve() }()
	defer func() { _ = car.Shutdown() }()
	carAddr := waitAddr(car.Addr)

	censor := NewMockCensor("127.0.0.1:0", "http://"+carAddr, "")
	go func() { _ = censor.Serve() }()
	defer func() { _ = censor.Shutdown() }()
	censorAddr := waitAddr(censor.Addr)

	node := scheduledFabric("car-sched", nil, car, nil)
	if err := node.PublishControl(ctx, "s1", msg); err != nil {
		t.Fatal(err)
	}

	client := scheduledFabric("car-sched", nil, nil, nil)
	reader := NewCARReader("http://" + censorAddr).WithPacer(fastCARPacer())
	got, err := client.ReadControlCAR(reader, 2)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("car roundtrip со смещением: got=%q err=%v", got, err)
	}

	// Если в этой эпохе смещение ненулевое, legacy-читатель (книга без
	// смещения) не должен молча восстановить тот же кадр.
	_, sched := node.scheduleNow(time.Now())
	if sched != nil && sched.CARWindowOffset != 0 {
		legacy := NewControlFabric([]byte("car-sched"), nil, nil, nil, nil)
		reader2 := NewCARReader("http://" + censorAddr).WithPacer(fastCARPacer())
		if got2, err2 := legacy.ReadControlCAR(reader2, 1); err2 == nil && bytes.Equal(got2, msg) {
			t.Fatal("legacy-читатель не должен восстанавливать кадр со смещением эпохи")
		}
	}
}

func TestScheduleChannelOrderPermutation(t *testing.T) {
	cf := scheduledFabric("ord", nil, nil, nil)
	ord := cf.channelOrder(time.Now())
	if len(ord) != 4 {
		t.Fatalf("ожидались 4 канала, получено %v", ord)
	}
	seen := make(map[string]bool)
	for _, c := range ord {
		seen[c] = true
	}
	for _, want := range []string{"board", "dns", "car", "ct"} {
		if !seen[want] {
			t.Fatalf("в перестановке нет канала %s: %v", want, ord)
		}
	}
	// Детерминизм: тот же момент — тот же порядок.
	again := cf.channelOrder(time.Now())
	for i := range ord {
		if ord[i] != again[i] {
			t.Fatal("channelOrder недетерминирован в пределах эпохи")
		}
	}
	// Legacy: фиксированный порядок.
	lg := NewControlFabric([]byte("ord"), nil, nil, nil, nil)
	got := lg.channelOrder(time.Now())
	if got[0] != "board" || got[1] != "dns" || got[2] != "car" || got[3] != "ct" {
		t.Fatalf("legacy порядок изменился: %v", got)
	}
}

// TestLegacyCombinerStillWorks — регрессия: без WithSchedule комбинер
// работает ровно как раньше (порядок board->dns->car, формат без эпох).
func TestLegacyCombinerStillWorks(t *testing.T) {
	ctx := context.Background()
	msg := []byte("next-entry=10.0.0.9:8443")

	cdn := NewCDNCacheStateChannel("127.0.0.1:0")
	dns := NewDNSBeacon("127.0.0.1:0", "dd.legacy.lab", "c", 5)
	go func() { _ = cdn.Serve() }()
	go func() { _ = dns.Serve() }()
	defer func() { _ = cdn.Shutdown() }()
	defer func() { _ = dns.Close() }()
	cdnAddr := waitAddr(cdn.Addr)
	dnsAddr := waitAddr(dns.LocalAddr)

	cf := NewControlFabric([]byte("legacy-seed"), cdn, nil, dns, nil)
	if cf.ScheduleEnabled() {
		t.Fatal("без WithSchedule этап F выключен")
	}
	if err := cf.PublishControl(ctx, "s1", msg); err != nil {
		t.Fatal(err)
	}

	dh, dp := hostPort(dnsAddr)
	dnsReader := NewDNSBeaconReader(dh, dp, "dd.legacy.lab", "c")
	got, via, err := cf.RecoverControlAny(ctx, "s1",
		NewCDNCacheStateClient("http://127.0.0.1:1"), dnsReader, nil, nil)
	if err != nil || via != "dns" || !bytes.Equal(got, msg) {
		t.Fatalf("legacy dns: via=%s got=%q err=%v", via, got, err)
	}
	got, via, err = cf.RecoverControlAny(ctx, "s1",
		NewCDNCacheStateClient("http://"+cdnAddr), nil, nil, nil)
	if err != nil || via != "board" || !bytes.Equal(got, msg) {
		t.Fatalf("legacy board: via=%s got=%q err=%v", via, got, err)
	}
}
