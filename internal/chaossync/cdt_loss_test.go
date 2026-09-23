package chaossync

// cdt_loss_test.go — устойчивость CDT к потерям фрагментов (реальный cross-border
// UDP теряет пакеты). Доказываем, что дефрагментер не встаёт на дыре: gap-skip
// перепрыгивает потерянные фрагменты, поток продолжается. IP не гарантирует
// доставку — верхние слои (TCP и т.п.) перешлют потерянное.

import (
	"bytes"
	"testing"
)

func TestCDTLossTolerance(t *testing.T) {
	master := bytes.Repeat([]byte{0x42}, 32)
	cfg := GeomConfig{}.withDefaults()
	frag := NewFragmenter(master, 9, cfg)
	defrag := NewDefragmenter(master, 9, cfg)
	payload := make([]byte, 200000)
	for i := range payload {
		payload[i] = byte(i*13 + 5)
	}
	frag.Push(payload)

	var wires [][]byte
	for {
		wire, _, ok := frag.Emit()
		if !ok {
			wire, _, ok = frag.EmitFinal()
			if !ok {
				break
			}
		}
		wires = append(wires, wire)
	}

	// роняем ~10% фрагментов (каждый десятый со сдвигом), ingest остальные по порядку
	dropped := 0
	var reassembled []byte
	for i, wire := range wires {
		if i%10 == 3 {
			dropped++
			continue
		}
		if !defrag.Ingest(wire) {
			t.Fatalf("фрагмент %d не опознан", i)
		}
		for {
			c := defrag.Next()
			if c == nil {
				break
			}
			reassembled = append(reassembled, c...)
		}
	}

	t.Logf("фрагментов=%d, потеряно=%d (%.0f%%), собрано=%d/%d байт",
		len(wires), dropped, 100*float64(dropped)/float64(len(wires)), len(reassembled), len(payload))

	// ключевое свойство: туннель НЕ встал на первой дыре. Первая потеря на ~3-м
	// фрагменте (~2 КБ); без gap-skip собралось бы ~2 КБ и стоп. С gap-skip собирается
	// существенно больше — поток живёт сквозь потери.
	if len(reassembled) < 50000 {
		t.Fatalf("туннель встал на дырах: собрано лишь %d байт — gap-skip не работает", len(reassembled))
	}
}
