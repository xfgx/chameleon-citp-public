package main

// autopilot_fitness_test.go — тест раунда 5: best-of-K выбор генома по
// fitness (novelty+leverage) и учёт живой экспозиции через leak-бюджет эпохи.

import (
	"strings"
	"testing"
	"time"

	"chameleon/internal/chameleon"
)

func mustEncodeTheta(t *testing.T, th chameleon.Theta) []byte {
	t.Helper()
	b, err := chameleon.EncodeTheta(th)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSelectGenomeFitness(t *testing.T) {
	m := newLayersTestManager(t)
	ap := NewAutopilot(m, nil)
	th := chameleon.DefaultTheta()
	ap.handleBoardMessage(chameleon.ThetaKind, mustEncodeTheta(t, th))

	entry := ServerEntry{Name: "n1", Addr: "203.0.113.1:9443", PubKey: "x", CFSeed: "seed"}
	desc := ap.rotateStrategyFor(entry, true)
	if !strings.Contains(desc, "θ-геном эпохи") || !strings.Contains(desc, "fitness") {
		t.Fatalf("desc=%q", desc)
	}
	if !strings.Contains(desc, "leak") {
		t.Fatalf("нет учёта leak в desc: %q", desc)
	}
	ap.mu.Lock()
	g := ap.lastGenome
	hist := len(ap.genomeHistory)
	lb := ap.leak
	ap.mu.Unlock()
	if g == nil || hist != 1 {
		t.Fatalf("genome/history: %+v %d", g, hist)
	}
	if lb == nil || lb.SpentFrac() <= 0 {
		t.Fatal("leak-бюджет не расходуется")
	}
	base := int(g.Flavor.Base / time.Millisecond)
	if base < th.BaseMsLo || base > th.BaseMsHi {
		t.Fatalf("base %d вне θ", base)
	}
	if g.Flavor.MaxPad < g.Flavor.MinPad+100 {
		t.Fatalf("pad %d..%d", g.Flavor.MinPad, g.Flavor.MaxPad)
	}

	// Второй поворот в той же эпохе: история растёт, тот же бюджет эпохи
	// продолжает расходоваться.
	_ = ap.rotateStrategyFor(entry, true)
	ap.mu.Lock()
	defer ap.mu.Unlock()
	if len(ap.genomeHistory) != 2 {
		t.Fatalf("history %d, want 2", len(ap.genomeHistory))
	}
	if ap.leak.SpentFrac() < 2.0/24.0-1e-9 {
		t.Fatalf("spent %v, want ≥2/24", ap.leak.SpentFrac())
	}
}
