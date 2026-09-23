package chameleon

import (
	"math"
	"testing"
)

// Профиль, вложенный в защищённый класс самого себя, даёт leverage ~1.
func TestLeverageSelfEmbedding(t *testing.T) {
	cand := FlowProfileFromFlavor("sber", Flavors["sber"])
	if l := LeverageScore(cand, DefaultProtectedClasses()); l < 0.99 {
		t.Fatalf("self leverage = %v, want ~1", l)
	}
}

// Далёкий от дорогих классов профиль (плотный CBR steam-dl) получает
// строго меньший leverage, чем профиль, вложенный в класс банка.
func TestLeverageDistantProfileLower(t *testing.T) {
	near := FlowProfileFromFlavor("sber", Flavors["sber"])
	far := FlowProfileFromFlavor("steam-dl", Flavors["steam-dl"])
	refs := DefaultProtectedClasses()
	ln, lf := LeverageScore(near, refs), LeverageScore(far, refs)
	if lf >= ln {
		t.Fatalf("steam-dl leverage %v >= sber %v", lf, ln)
	}
}

func TestHistogramIntersectionBounds(t *testing.T) {
	a := []float64{1, 0, 0}
	if v := HistogramIntersection(a, a); math.Abs(v-1) > 1e-9 {
		t.Fatalf("identical = %v", v)
	}
	if v := HistogramIntersection(a, []float64{0, 0, 1}); v != 0 {
		t.Fatalf("disjoint = %v", v)
	}
}

func TestMMD2Identical(t *testing.T) {
	xs := [][]float64{{0.1, 0.2}, {0.3, 0.4}}
	if v := MMD2(xs, xs, 1.0); v > 1e-9 {
		t.Fatalf("mmd(x,x) = %v", v)
	}
}

// Карта дорогих зон: сборка, leverage лучшего кандидата, JSON-конверт борда.
func TestCollateralMapRoundtrip(t *testing.T) {
	m := NewCollateralMap("AS12345", []FlowProfile{FlowProfileFromFlavor("sber", Flavors["sber"])})
	if m.Kind != CollateralKind || len(m.Zones) == 0 {
		t.Fatalf("map: %+v", m)
	}
	var sberZone *CollateralZone
	for i := range m.Zones {
		if m.Zones[i].Class == "sber" {
			sberZone = &m.Zones[i]
		}
	}
	if sberZone == nil || sberZone.Leverage < 0.99 {
		t.Fatalf("sber zone: %+v", sberZone)
	}
	b, err := EncodeCollateralMap(m)
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeCollateralMap(b)
	if err != nil || back.AS != "AS12345" {
		t.Fatalf("decode: %v %+v", err, back)
	}
	if _, err := DecodeCollateralMap([]byte(`{"kind":"node-hint"}`)); err == nil {
		t.Fatal("wrong kind accepted")
	}
}

func TestFitnessScore(t *testing.T) {
	terms := FitnessTerms{Survival: 1, Novelty: 1, Background: 1, Leverage: 1}
	if s := terms.Score(DefaultFitnessWeights()); math.Abs(s-1) > 1e-9 {
		t.Fatalf("all-ones score = %v", s)
	}
	if s := (FitnessTerms{}).Score(DefaultFitnessWeights()); s != 0 {
		t.Fatalf("zero score = %v", s)
	}
	// leverage-вклад с дефолтными весами = 0.2.
	if s := (FitnessTerms{Leverage: 1}).Score(DefaultFitnessWeights()); s < 0.19 || s > 0.21 {
		t.Fatalf("leverage-only = %v, want ~0.2", s)
	}
}

func TestFlowProfileFromSamples(t *testing.T) {
	p := FlowProfileFromSamples("x", []int{100, 200, 300}, []float64{10, 20, 30})
	if len(p.SizeHist) != flowHistBins || len(p.IATHist) != flowHistBins {
		t.Fatalf("hist dims")
	}
	sum := 0.0
	for _, v := range p.SizeHist {
		sum += v
	}
	if math.Abs(sum-1) > 1e-9 {
		t.Fatalf("size hist not normalized: %v", sum)
	}
	if len(p.Scalar) != 5 {
		t.Fatalf("scalar dim %d", len(p.Scalar))
	}
}
