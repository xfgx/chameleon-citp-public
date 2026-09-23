package main

// cf_broadcast_test.go — тесты рассыльщика θ/карты дорогих зон (слои 6/8).

import (
	"context"
	"testing"
	"time"

	"chameleon/internal/chameleon"
)

func TestSessionRegistry(t *testing.T) {
	r := newSessionRegistry()
	pub := make([]byte, 32)
	pub[0] = 1
	r.Add(pub)
	r.Add(pub) // дедуп
	if len(r.List()) != 1 {
		t.Fatalf("registry size %d, want 1", len(r.List()))
	}
	// TTL: записи старше 6 часов отсеиваются.
	r.m[[32]byte{2}] = time.Now().Add(-7 * time.Hour)
	if len(r.List()) != 1 {
		t.Fatalf("ttl prune: %d, want 1", len(r.List()))
	}
	// Невалидная длина ключа игнорируется.
	r.Add([]byte("short"))
	if len(r.List()) != 1 {
		t.Fatal("short key accepted")
	}
}

// PublishTo: θ и slim-карта уезжают однокадровыми сообщениями в каналы
// клиента; broadcastAll догоняет всех зарегистрированных.
func TestThetaBroadcasterPublishTo(t *testing.T) {
	cdn := chameleon.NewCDNCacheStateChannel("127.0.0.1:0")
	go func() { _ = cdn.Serve() }()
	defer func() { _ = cdn.Shutdown() }()
	deadline := time.Now().Add(3 * time.Second)
	for cdn.Addr() == "" {
		if time.Now().After(deadline) {
			t.Fatal("cdn не поднялся")
		}
		time.Sleep(10 * time.Millisecond)
	}
	boardURL := "http://" + cdn.Addr()

	seedText := "test-seed-bc"
	cf := chameleon.NewControlFabric([]byte("chameleon-control-fabric:"+seedText), cdn, nil, nil, nil).
		WithSchedule(nil, 0)
	reg := newSessionRegistry()
	pub := make([]byte, 32)
	pub[0] = 7
	reg.Add(pub)
	bc := NewThetaBroadcaster(cf, reg, chameleon.DefaultTheta(), "AS12345")

	bc.PublishTo(pub, time.Now())
	ctx := context.Background()
	thetaID := chameleon.ControlSessionIDFor(pub, "theta")
	msgs, err := chameleon.PollChannelMessages(ctx, boardURL, seedText, thetaID)
	if err != nil || len(msgs) != 1 {
		t.Fatalf("theta msgs %d err %v", len(msgs), err)
	}
	if _, err := chameleon.DecodeTheta(msgs[0]); err != nil {
		t.Fatalf("theta decode: %v", err)
	}
	collID := chameleon.ControlSessionIDFor(pub, "collateral")
	cmsgs, err := chameleon.PollChannelMessages(ctx, boardURL, seedText, collID)
	if err != nil || len(cmsgs) != 1 {
		t.Fatalf("collateral msgs %d err %v", len(cmsgs), err)
	}
	if k := chameleon.ControlMessageKind(cmsgs[0]); k != chameleon.CollateralKind {
		t.Fatalf("kind %q", k)
	}

	// Смена эпохи: broadcastAll дописывает вторую θ; клиент берёт последнюю.
	bc.broadcastAll(time.Now())
	msgs, err = chameleon.PollChannelMessages(ctx, boardURL, seedText, thetaID)
	if err != nil || len(msgs) != 2 {
		t.Fatalf("theta msgs после broadcastAll %d err %v, want 2", len(msgs), err)
	}
	if _, err := chameleon.DecodeTheta(msgs[len(msgs)-1]); err != nil {
		t.Fatalf("latest theta decode: %v", err)
	}
}
