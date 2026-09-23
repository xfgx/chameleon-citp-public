package chameleon

import (
	"testing"
	"time"
)

// Одноразовость генома: детерминизм по (seed, epoch, client) и сдвиг точки
// при смене любого входа.
func TestDeriveGenomeDeterministic(t *testing.T) {
	th := DefaultTheta()
	seed := []byte("test-session-seed-32-bytes-padded!!")
	epoch := uint64(496600)
	a := DeriveGenome(th, seed, epoch, []byte("client-A"))
	b := DeriveGenome(th, seed, epoch, []byte("client-A"))
	if a.Flavor != b.Flavor || a.Fingerprint != b.Fingerprint || a.Canary != b.Canary {
		t.Fatalf("non-deterministic: %+v vs %+v", a, b)
	}
	if c := DeriveGenome(th, seed, epoch, []byte("client-B")); c.Fingerprint == a.Fingerprint {
		t.Fatalf("client change did not move genome")
	}
	if d := DeriveGenome(th, seed, epoch+1, []byte("client-A")); d.Fingerprint == a.Fingerprint {
		t.Fatalf("epoch change did not move genome")
	}
}

// Все выборки лежат внутри θ-границ; maxPad никогда не уже minPad+100.
func TestDeriveGenomeBounds(t *testing.T) {
	th := DefaultTheta()
	seed := []byte("bounds-seed")
	for i := 0; i < 300; i++ {
		g := DeriveGenome(th, seed, uint64(496600+i), []byte("c"))
		base := int(g.Flavor.Base / time.Millisecond)
		jit := int(g.Flavor.Jitter / time.Millisecond)
		if base < th.BaseMsLo || base > th.BaseMsHi {
			t.Fatalf("base %d out of [%d,%d]", base, th.BaseMsLo, th.BaseMsHi)
		}
		if jit < 1 || jit > th.JitterHi {
			t.Fatalf("jitter %d", jit)
		}
		if g.Flavor.MinPad < th.MinPadLo || g.Flavor.MinPad > th.MinPadHi {
			t.Fatalf("minpad %d", g.Flavor.MinPad)
		}
		if g.Flavor.MaxPad < g.Flavor.MinPad+100 || g.Flavor.MaxPad > th.MaxPadHi+100 {
			t.Fatalf("maxpad %d (minpad %d)", g.Flavor.MaxPad, g.Flavor.MinPad)
		}
	}
}

// Канареечная доля близка к CanaryFrac; канарейка статистически заметнее
// (джиттер не выше четверти базы).
func TestCanaryFraction(t *testing.T) {
	th := DefaultTheta() // 0.05
	seed := []byte("canary-seed")
	n, c := 4000, 0
	for i := 0; i < n; i++ {
		id := []byte{byte(i), byte(i >> 8), byte(i >> 16)}
		g := DeriveGenome(th, seed, 496600, id)
		if g.Canary {
			c++
			if g.Flavor.Jitter > g.Flavor.Base/4 {
				t.Fatalf("canary jitter %v > base/4 %v", g.Flavor.Jitter, g.Flavor.Base/4)
			}
		}
	}
	frac := float64(c) / float64(n)
	if frac < 0.02 || frac > 0.09 {
		t.Fatalf("canary frac %v, want ~0.05", frac)
	}
}

// Бюджет утечки: выбор проб по gain/leak, атомарное списание, точное
// израсходование остатка, отказ при исчерпании.
func TestLeakBudgetAndProbeSelection(t *testing.T) {
	b := NewLeakBudget(496600, 10)
	cands := []ProbeCandidate{
		{Name: "low-value", GainBits: 1, LeakBits: 4},
		{Name: "best", GainBits: 8, LeakBits: 4},
		{Name: "mid", GainBits: 3, LeakBits: 3},
	}
	sel := SelectProbes(cands, b)
	if len(sel) != 2 || sel[0].Name != "best" || sel[1].Name != "mid" {
		t.Fatalf("selection: %+v", sel)
	}
	if rem := b.Remaining(); rem != 3 {
		t.Fatalf("remaining %v, want 3", rem)
	}
	// Остаток 3 бита: из тех же кандидатов помещается только «mid» (ровно 3).
	if s2 := SelectProbes(cands, b); len(s2) != 1 || s2[0].Name != "mid" {
		t.Fatalf("second selection: %+v", s2)
	}
	if rem := b.Remaining(); rem != 0 {
		t.Fatalf("remaining %v, want 0", rem)
	}
	// Бюджет исчерпан полностью: следующий выбор пуст.
	if s3 := SelectProbes(cands, b); len(s3) != 0 {
		t.Fatalf("budget not enforced: %+v", s3)
	}
	if b.SpentFrac() != 1.0 {
		t.Fatalf("spent frac %v", b.SpentFrac())
	}
}

// θ-конверт борда и обратная совместимость классификатора сообщений.
func TestThetaRoundtripAndKind(t *testing.T) {
	th := DefaultTheta()
	b, err := EncodeTheta(th)
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeTheta(b)
	if err != nil || back.CanaryFrac != th.CanaryFrac {
		t.Fatalf("theta roundtrip: %v", err)
	}
	if k := ControlMessageKind(b); k != ThetaKind {
		t.Fatalf("kind %q", k)
	}
	hint := []byte(`{"node_ip":"203.0.113.1","pc_ip_mode":"auto"}`)
	if k := ControlMessageKind(hint); k != "node-hint" {
		t.Fatalf("hint classified as %q", k)
	}
	if _, err := DecodeTheta(hint); err == nil {
		t.Fatal("hint accepted as theta")
	}
}
