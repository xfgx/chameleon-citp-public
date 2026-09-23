package chaossync

// cdt_rotate_test.go — непрерывный CDT-туннель: ротация геометрии и data-ключа
// по эпохам хаоса (T). Доказываем, что поток собирается ЦЕЛИКОМ сквозь множество
// ротаций (мутация узора по T не рвёт туннель), а глобальный seq держит порядок.
// Это то, что нужно для реального сеанса длиной во много эпох (видео).

import (
	"bytes"
	"testing"
	"time"
)

func TestCDTRotationMultiEpoch(t *testing.T) {
	master := bytes.Repeat([]byte{0x42}, 32)
	cfg := GeomConfig{}.withDefaults()
	T := uint64(8) // 8 сек на эпоху
	base := time.Unix(1_700_000_000, 0)

	frag := NewRotatingFragmenter(master, cfg, T, base)
	defrag := NewRotatingDefragmenter(master, cfg, T, base)

	payload := make([]byte, 60000)
	for i := range payload {
		payload[i] = byte(i*17 + 3)
	}
	frag.Push(payload)

	var reassembled []byte
	now := base
	frags := 0
	epochsSeen := map[uint64]bool{}

	// Гоним фрагменты, продвигая wall-clock так, чтобы эпоха менялась много раз
	// за передачу (1 сек на фрагмент, эпоха 8с → ротация каждые ~8 фрагментов).
	for guard := 0; guard < 100000; guard++ {
		frag.TickEpoch(now)
		defrag.TickEpoch(now)
		epochsSeen[frag.Epoch()] = true

		wire, _, ok := frag.Emit()
		if !ok {
			wire, _, ok = frag.EmitFinal()
			if !ok {
				if frag.Buffered() == 0 {
					break
				}
				now = now.Add(time.Second)
				continue
			}
		}
		if !defrag.Ingest(wire) {
			t.Fatalf("нода не опознала фрагмент %d на эпохе %d", frags, frag.Epoch())
		}
		frags++
		for {
			c := defrag.Next()
			if c == nil {
				break
			}
			reassembled = append(reassembled, c...)
		}
		now = now.Add(time.Second)
	}

	if len(epochsSeen) < 3 {
		t.Fatalf("тест не нагнал ротаций: эпох затронуто %d", len(epochsSeen))
	}
	if !bytes.Equal(reassembled, payload) {
		t.Fatalf("непрерывный туннель разошёлся: got %d байт, want %d", len(reassembled), len(payload))
	}
	t.Logf("непрерывный туннель сквозь ротацию ОК: %d байт, %d фрагментов, эпох затронуто=%d",
		len(reassembled), frags, len(epochsSeen))
}
