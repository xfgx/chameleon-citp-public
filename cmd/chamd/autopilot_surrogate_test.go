package main

// autopilot_surrogate_test.go — тесты раунда 4: суррогат в автопилоте
// (слой 1) и двусторонний учёт канареек (слой 3).

import (
	"path/filepath"
	"testing"
	"time"

	"chameleon/internal/chameleon"
)

// Слой 1: автопилот переобучает суррогат на журнале наблюдений own+exo.
func TestRetrainSurrogate(t *testing.T) {
	ap := NewAutopilot(newLayersTestManager(t), nil)
	dir := t.TempDir()
	ap.SetDataDir(dir)
	now := time.Now().UTC().Format(time.RFC3339)
	obs := []chameleon.NetObservation{
		{TS: now, Src: chameleon.SrcOwn, HasDPI: true, TCPReset: true},
		{TS: now, Src: chameleon.SrcOwn, HasDPI: true, TCPReset: true},
		{TS: now, Src: chameleon.SrcExo},
		{TS: now, Src: chameleon.SrcExo},
	}
	if _, err := chameleon.AppendObservations(filepath.Join(dir, "netprofile.jsonl"), obs, 1<<20, 256); err != nil {
		t.Fatal(err)
	}
	ap.retrainSurrogate()
	ap.mu.Lock()
	s := ap.surrogate
	ap.mu.Unlock()
	if s == nil {
		t.Fatal("суррогат не обучен")
	}
	if p := s.Predict([]float64{1, 0, 1, 0, 0}); p < 0.5 {
		t.Fatalf("p(блок|dpi+rst)=%v, want >0.5", p)
	}
	if p := s.Predict([]float64{0, 0, 0, 0, 0}); p > 0.5 {
		t.Fatalf("p(блок|чисто)=%v, want <0.5", p)
	}
}

// Рукопожатие не доказывает устойчивость ни канареечного, ни обычного генома.
func TestCanaryHandshakeIsNotSurvival(t *testing.T) {
	ap := NewAutopilot(newLayersTestManager(t), nil)
	th := chameleon.DefaultTheta()
	g := chameleon.DeriveGenome(th, []byte("seed"), 1, []byte("c"))
	g.Canary = true
	ap.mu.Lock()
	ap.lastGenome = &g
	ap.mu.Unlock()
	ap.OnSessionUp()
	if ap.canaries.Samples() != 0 {
		t.Fatalf("handshake ошибочно записан как устойчивость: samples=%d", ap.canaries.Samples())
	}
	g2 := chameleon.DeriveGenome(th, []byte("seed"), 1, []byte("d"))
	g2.Canary = false
	ap.mu.Lock()
	ap.lastGenome = &g2
	ap.mu.Unlock()
	ap.OnSessionUp()
	if ap.canaries.Samples() != 0 {
		t.Fatalf("лишняя запись: samples=%d, want 0", ap.canaries.Samples())
	}
}
