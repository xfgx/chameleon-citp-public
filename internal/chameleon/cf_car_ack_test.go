package chameleon

// cf_car_ack_test.go — Этап B3: обратный канал клиент→нода. В лаборатории
// RST производит сам отправитель; для ноды это неотличимо от RST-инъекции
// ТСПУ (соединение умирает до передачи данных).

import (
	"testing"
	"time"
)

func TestCARAckChannelLoopback(t *testing.T) {
	obs := NewCARAckObserver("127.0.0.1:0")
	go func() { _ = obs.Serve() }()
	addr := waitAddr(obs.Addr)
	defer func() { _ = obs.Close() }()

	sender := NewCARAckSender()
	sender.Burst = 3
	sender.Gap = 30 * time.Millisecond

	want := []uint8{1, 0, 1, 1, 0}
	const window = 300 * time.Millisecond

	// Наблюдатель открывает окна ПЕРВЫМ; отправитель стартует в середине
	// первого окна — всплеск (3 RST × 30мс ≈ 90мс) целиком попадает в своё
	// окно с запасом по краям, гонка синхронизации исключена.
	gotCh := make(chan []uint8, 1)
	go func() {
		gotCh <- obs.ReadBits(len(want), window, 2)
	}()

	time.Sleep(window / 2)
	sender.SendBits(addr, want, window)
	got := <-gotCh

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("бит %d: got %d want %d (весь кадр: got %v want %v)", i, got[i], want[i], got, want)
		}
	}
}

// Тишина на линии — все нули, ложных срабатываний нет.
func TestCARAckSilenceReadsZeros(t *testing.T) {
	obs := NewCARAckObserver("127.0.0.1:0")
	go func() { _ = obs.Serve() }()
	_ = waitAddr(obs.Addr)
	defer func() { _ = obs.Close() }()

	got := obs.ReadBits(2, 150*time.Millisecond, 2)
	if got[0] != 0 || got[1] != 0 {
		t.Fatalf("тишина должна читаться нулями, got %v", got)
	}
}
