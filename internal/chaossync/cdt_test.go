package chaossync

// cdt_test.go — проверка CDT (Chaos-Dispersed Transport):
//  1) детерминизм геометрии (обе стороны выводят одинаково; мутация эпохи меняет её);
//  2) round-trip: поток растворяется в фрагменты и собирается обратно без потерь;
//  3) НЕСВЯЗУЕМОСТЬ (ядро новизны): по наблюдаемой геометрии нельзя собрать поток —
//     нет стабильного 5-tuple, порты/размеры/тайминги max-entropy.

import (
	"bytes"
	"math"
	"testing"
)

func TestCDTGeometryDeterminism(t *testing.T) {
	master := bytes.Repeat([]byte{0x42}, 32)
	cfg := GeomConfig{}.withDefaults()
	a := NewGeometrySource(master, 5, cfg)
	b := NewGeometrySource(master, 5, cfg)
	for i := 0; i < 5000; i++ {
		ga, gb := a.Next(), b.Next()
		if ga != gb {
			t.Fatalf("геометрия разошлась на фрагменте %d", i)
		}
	}
	// другая эпоха — другая геометрия (мутация узора по T)
	c := NewGeometrySource(master, 6, cfg)
	a2 := NewGeometrySource(master, 5, cfg)
	same := 0
	for i := 0; i < 1000; i++ {
		if a2.Next() == c.Next() {
			same++
		}
	}
	if same > 50 { // случайно совпасть могут лишь единицы
		t.Fatalf("геометрия не мутирует между эпохами: %d совпадений из 1000", same)
	}
}

func TestCDTRoundtrip(t *testing.T) {
	master := bytes.Repeat([]byte{0x42}, 32)
	cfg := GeomConfig{}.withDefaults()
	payload := make([]byte, 100000) // 100 КБ имитации данных
	for i := range payload {
		payload[i] = byte(i*31 + 7)
	}

	frag := NewFragmenter(master, 9, cfg)
	defrag := NewDefragmenter(master, 9, cfg)
	frag.Push(payload)

	var reassembled []byte
	fragCount := 0
	for {
		wire, _, ok := frag.Emit()
		if !ok {
			wire, _, ok = frag.EmitFinal()
			if !ok {
				break
			}
		}
		if !defrag.Ingest(wire) {
			t.Fatalf("нода не опознала фрагмент %d", fragCount)
		}
		fragCount++
		for {
			c := defrag.Next()
			if c == nil {
				break
			}
			reassembled = append(reassembled, c...)
		}
	}
	if !bytes.Equal(reassembled, payload) {
		t.Fatalf("round-trip разошёлся: got %d байт, want %d", len(reassembled), len(payload))
	}
	t.Logf("round-trip OK: %d байт растворено в %d фрагментов и собрано обратно без потерь", len(payload), fragCount)
}

// TestCDTUnlinkability — ядро новизны CDT: наблюдатель не может сгруппировать
// фрагменты в один поток. Меряем наблюдаемую геометрию: уникальность 5-tuple,
// длина серий одного tuple, энтропию портов/размеров/интервалов.
func TestCDTUnlinkability(t *testing.T) {
	master := bytes.Repeat([]byte{0x42}, 32)
	cfg := GeomConfig{}.withDefaults()
	frag := NewFragmenter(master, 9, cfg)
	payload := make([]byte, 200000)
	frag.Push(payload)

	type obs struct{ src, dst, size, gap int }
	var seq []obs
	for {
		wire, g, ok := frag.Emit()
		if !ok {
			wire, g, ok = frag.EmitFinal()
			if !ok {
				break
			}
		}
		seq = append(seq, obs{g.SrcPort, g.DestPort, len(wire), g.GapUs})
	}
	if len(seq) < 200 {
		t.Fatalf("мало фрагментов для статистики: %d", len(seq))
	}

	// 1) уникальность наблюдаемого (src,dst)-tuple
	tuples := map[[2]int]int{}
	var dsts, sizes, gaps []int
	for _, o := range seq {
		tuples[[2]int{o.src, o.dst}]++
		dsts = append(dsts, o.dst)
		sizes = append(sizes, o.size)
		gaps = append(gaps, o.gap)
	}
	uniqRatio := float64(len(tuples)) / float64(len(seq))

	// 2) макс. серия подряд идущих фрагментов с одним tuple
	maxRun, run := 1, 1
	for i := 1; i < len(seq); i++ {
		if seq[i].src == seq[i-1].src && seq[i].dst == seq[i-1].dst {
			run++
			if run > maxRun {
				maxRun = run
			}
		} else {
			run = 1
		}
	}

	// 3) энтропия наблюдаемых величин (max-entropy shaping)
	entPort := entropyOf(dsts)
	entSize := entropyOf(sizes)
	entGap := entropyOf(gaps)
	maxEntPort := math.Log2(float64(cfg.PortCount))

	t.Logf("фрагментов=%d  уникальных tuple=%d (%.1f%%)  макс.серия одного tuple=%d",
		len(seq), len(tuples), 100*uniqRatio, maxRun)
	t.Logf("энтропия: dstPort=%.2f бит (макс %.2f, %.0f%%)  size=%.2f бит  gap=%.2f бит",
		entPort, maxEntPort, 100*entPort/maxEntPort, entSize, entGap)

	if maxRun > cfg.MaxFlow {
		t.Errorf("серия одного 5-tuple %d превышает MaxFlow=%d — поток собираем", maxRun, cfg.MaxFlow)
	}
	if entPort < 0.85*maxEntPort {
		t.Errorf("энтропия портов низкая: %.2f < 85%% от %.2f — геометрия не max-entropy", entPort, maxEntPort)
	}
	if uniqRatio < 0.5 {
		t.Errorf("слишком мало уникальных tuple: %.2f — фрагменты связываемы", uniqRatio)
	}
}

// entropyOf — энтропия Шенона наблюдаемой дискретной величины (биты).
func entropyOf(vals []int) float64 {
	counts := map[int]int{}
	for _, v := range vals {
		counts[v]++
	}
	n := float64(len(vals))
	h := 0.0
	for _, c := range counts {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
