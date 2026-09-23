package chameleon

// cf_board_channels_test.go — тесты broadcast-каналов борда (слои 6/8).

import (
	"context"
	"testing"
	"time"
)

// Однокадровые сообщения broadcast-каналов: независимая расшифровка,
// «последний валидный» при накоплении публикаций, изоляция по seed и каналу.
func TestPublishControlSingleChannels(t *testing.T) {
	cdn := NewCDNCacheStateChannel("127.0.0.1:0")
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

	seedText := "test-seed-broadcast"
	cf := NewControlFabric([]byte("chameleon-control-fabric:"+seedText), cdn, nil, nil, nil).
		WithSchedule(nil, 0)
	pub := make([]byte, 32)
	pub[0] = 7

	// Две публикации θ в один канал (как две эпохи подряд): обе накопятся.
	th := DefaultTheta()
	b1, _ := EncodeTheta(th)
	if err := cf.PublishControlSingle(ControlSessionIDFor(pub, "theta"), b1); err != nil {
		t.Fatal(err)
	}
	th2 := th
	th2.LeakBits = 48
	b2, _ := EncodeTheta(th2)
	if err := cf.PublishControlSingle(ControlSessionIDFor(pub, "theta"), b2); err != nil {
		t.Fatal(err)
	}
	// Карта — в соседний канал; hint-канал не тронут.
	cm := NewCollateralMap("AS12345", nil).Slim()
	cb, err := EncodeCollateralMapSlim(cm)
	if err != nil {
		t.Fatal(err)
	}
	if err := cf.PublishControlSingle(ControlSessionIDFor(pub, "collateral"), cb); err != nil {
		t.Fatal(err)
	}

	msgs, err := PollChannelMessages(context.Background(), boardURL, seedText, ControlSessionIDFor(pub, "theta"))
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 {
		t.Fatalf("theta msgs %d, want 2", len(msgs))
	}
	back, err := DecodeTheta(msgs[len(msgs)-1])
	if err != nil || back.LeakBits != 48 {
		t.Fatalf("latest theta: %v %+v", err, back)
	}

	cmsgs, err := PollChannelMessages(context.Background(), boardURL, seedText, ControlSessionIDFor(pub, "collateral"))
	if err != nil || len(cmsgs) != 1 {
		t.Fatalf("collateral msgs %d err %v", len(cmsgs), err)
	}
	if k := ControlMessageKind(cmsgs[0]); k != CollateralKind {
		t.Fatalf("kind %q, want %q", k, CollateralKind)
	}

	// Каналы клиентов не пересекаются: у другого клиента — пусто.
	other := make([]byte, 32)
	other[0] = 9
	none, err := PollChannelMessages(context.Background(), boardURL, seedText, ControlSessionIDFor(other, "theta"))
	if err != nil {
		t.Fatal(err)
	}
	if len(none) != 0 {
		t.Fatalf("cross-client leak: %d msgs", len(none))
	}

	// Чужой seed: кадры не дешифруются — для посторонних канал пуст.
	none, err = PollChannelMessages(context.Background(), boardURL, "wrong-seed", ControlSessionIDFor(pub, "theta"))
	if err != nil {
		t.Fatal(err)
	}
	if len(none) != 0 {
		t.Fatalf("wrong seed decoded %d msgs", len(none))
	}
}

// ControlSessionIDFor: детерминизм, разделение каналов, формат как у sid.
func TestControlSessionIDFor(t *testing.T) {
	pub := make([]byte, 32)
	a := ControlSessionIDFor(pub, "theta")
	if a != ControlSessionIDFor(pub, "theta") {
		t.Fatal("недетерминированный id")
	}
	if a == ControlSessionIDFor(pub, "collateral") {
		t.Fatal("каналы не разделены")
	}
	if a == ControlSessionID(pub) {
		t.Fatal("пересечение с hint-каналом")
	}
	if len(a) != len(ControlSessionID(pub)) {
		t.Fatalf("len %d, want %d", len(a), len(ControlSessionID(pub)))
	}
}
