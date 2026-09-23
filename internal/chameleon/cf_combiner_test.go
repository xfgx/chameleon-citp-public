package chameleon

// cf_combiner_test.go — Этап D4: комбинер каналов. Критерий roadmap: при
// выключении любых двух каналов команда всё равно доходит по оставшимся.

import (
	"context"
	"testing"
)

func TestControlFabricChannelCombiner(t *testing.T) {
	ctx := context.Background()
	msg := []byte("next-entry=10.0.0.9:8443")

	// Полный стенд: board + DNS + CAR(+MockCensor).
	cdn := NewCDNCacheStateChannel("127.0.0.1:0")
	car := NewCARChannel("127.0.0.1:0")
	dns := NewDNSBeacon("127.0.0.1:0", "dd.phantom.lab", "c", 5)
	go func() { _ = cdn.Serve() }()
	go func() { _ = car.Serve() }()
	go func() { _ = dns.Serve() }()
	cdnAddr := waitAddr(cdn.Addr)
	carAddr := waitAddr(car.Addr)
	dnsAddr := waitAddr(dns.LocalAddr)
	defer func() { _ = cdn.Shutdown() }()
	defer func() { _ = car.Shutdown() }()
	defer func() { _ = dns.Close() }()

	censor := NewMockCensor("127.0.0.1:0", "http://"+carAddr, "")
	go func() { _ = censor.Serve() }()
	censorAddr := waitAddr(censor.Addr)
	defer func() { _ = censor.Shutdown() }()

	cf := NewControlFabric([]byte("combiner-seed"), cdn, car, dns, nil)
	if err := cf.PublishControl(ctx, "s1", msg); err != nil {
		t.Fatal(err)
	}

	boardUp := NewCDNCacheStateClient("http://" + cdnAddr)
	boardDown := NewCDNCacheStateClient("http://127.0.0.1:1") // мёртвый порт
	dh, dp := hostPort(dnsAddr)
	dnsReader := NewDNSBeaconReader(dh, dp, "dd.phantom.lab", "c")
	carReader := NewCARReader("http://" + censorAddr).WithPacer(fastCARPacer())

	// 1) Все каналы живы — выигрывает board (первый в политике).
	got, via, err := cf.RecoverControlAny(ctx, "s1", boardUp, dnsReader, carReader, nil)
	if err != nil || string(got) != string(msg) || via != "board" {
		t.Fatalf("все живы: via=%s got=%q err=%v", via, got, err)
	}

	// 2) Board мёртв -> DNS (зашифрованный чанк на seq 1).
	got, via, err = cf.RecoverControlAny(ctx, "s1", boardDown, dnsReader, nil, nil)
	if err != nil || string(got) != string(msg) || via != "dns" {
		t.Fatalf("board мёртв: via=%s got=%q err=%v", via, got, err)
	}

	// 3) Board + DNS мертвы -> CAR (кадр через кодовую книгу и цензор).
	got, via, err = cf.RecoverControlAny(ctx, "s1", boardDown, nil, carReader, nil)
	if err != nil || string(got) != string(msg) || via != "car" {
		t.Fatalf("board+dns мертвы: via=%s got=%q err=%v", via, got, err)
	}

	// 4) Все каналы мертвы -> честная ошибка.
	if _, _, err = cf.RecoverControlAny(ctx, "s1", boardDown, nil, nil, nil); err == nil {
		t.Fatal("при мёртвых каналах обязана быть ошибка")
	}
}
