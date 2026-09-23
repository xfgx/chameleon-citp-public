package chameleon

import (
	"math"
	"testing"
	"time"
)

// Суррогат учится на разделимой выборке: вектор признаков -> вердикт.
func TestSurrogateLearnsSeparable(t *testing.T) {
	s := NewSurrogate(5)
	for epoch := 0; epoch < 300; epoch++ {
		s.Learn([]float64{1, 0, 1, 0, 0}, 1, 1, 0.5)
		s.Learn([]float64{0, 1, 0, 1, 0}, 0, 1, 0.5)
	}
	if p := s.Predict([]float64{1, 0, 1, 0, 0}); p < 0.9 {
		t.Fatalf("pos p=%v", p)
	}
	if p := s.Predict([]float64{0, 1, 0, 1, 0}); p > 0.1 {
		t.Fatalf("neg p=%v", p)
	}
}

// Федеративный путь: слитые статистики двух клиентов дают тот же шаг, что
// одна статистика по объединённой выборке.
func TestFederatedStatsMerge(t *testing.T) {
	xs := [][]float64{{1, 0, 0, 0, 0}, {0, 1, 0, 0, 0}, {1, 1, 0, 0, 0}, {0, 0, 1, 0, 0}}
	ys := []float64{1, 0, 1, 0}

	a := NewSurrogate(5)
	ga := a.StatsFrom(xs[:2], ys[:2], nil)
	gb := a.StatsFrom(xs[2:], ys[2:], nil)
	merged := MergeGradStats(ga, gb)
	if merged.N != 4 {
		t.Fatalf("merged N=%d", merged.N)
	}
	a.ApplyStats(merged, 0.3)

	b := NewSurrogate(5)
	b.ApplyStats(b.StatsFrom(xs, ys, nil), 0.3)

	for i := range a.W {
		if math.Abs(a.W[i]-b.W[i]) > 1e-9 {
			t.Fatalf("w[%d]: %v vs %v", i, a.W[i], b.W[i])
		}
	}
	if math.Abs(a.B-b.B) > 1e-9 {
		t.Fatalf("bias %v vs %v", a.B, b.B)
	}
}

// Обучение по журналу наблюдений: веса источника и recency-забывание.
func TestTrainFromObservationsWeights(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	obs := []NetObservation{
		{TS: now.Format(time.RFC3339), Src: SrcOwn, Trust: TrustOwn, HasDPI: true, TCPReset: true},
		{TS: now.Add(-30 * 24 * time.Hour).Format(time.RFC3339), Src: SrcExo, Trust: TrustExo},
	}
	s := NewSurrogate(5)
	if n := s.TrainFromObservations(obs, now, 7*24*time.Hour, 0.5); n != 2 {
		t.Fatalf("trained %d", n)
	}
	// Свежая своя блок-запись двигает модель к предсказанию блока сильнее,
	// чем старая чужая чистая — к обратному.
	if p := s.Predict([]float64{1, 0, 1, 0, 0}); p < 0.5 {
		t.Fatalf("p=%v", p)
	}
}

// GradStats — конверт борда с kind-маркером.
func TestGradStatsEncodeKind(t *testing.T) {
	s := NewSurrogate(5)
	g := s.StatsFrom([][]float64{{1, 0, 0, 0, 0}}, []float64{1}, nil)
	b, err := g.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if k := ControlMessageKind(b); k != GradStatsKind {
		t.Fatalf("kind %q", k)
	}
	back, err := DecodeGradStats(b)
	if err != nil || back.N != 1 {
		t.Fatalf("decode: %v %+v", err, back)
	}
}

// Novelty: одинокий геном = 1; близкий к популяции менее «нов», чем далёкий.
func TestNoveltyScore(t *testing.T) {
	th := DefaultTheta()
	seed := []byte("nov-seed")
	g1 := DeriveGenome(th, seed, 1, []byte("a"))
	g2 := DeriveGenome(th, seed, 1, []byte("b"))
	g3 := DeriveGenome(th, seed, 1, []byte("c"))
	if v := NoveltyScore(g1, nil, 3); v != 1 {
		t.Fatalf("singleton novelty %v", v)
	}
	pop := []Genome{g1, g2, g3}
	far := g1
	far.Fingerprint = "far"
	far.Flavor.Base = 300 * time.Millisecond
	far.Flavor.MaxPad = 1500
	near := g1
	near.Fingerprint = "near"
	if NoveltyScore(near, pop, 1) >= NoveltyScore(far, pop, 1) {
		t.Fatalf("near novelty >= far novelty")
	}
}

// Канарейки: триггер срабатывает только при достаточной выборке и
// выживаемости ниже порога.
func TestCanaryTrigger(t *testing.T) {
	tr := &CanaryTracker{}
	if tr.ShouldBumpEpoch(0.5, 10) {
		t.Fatal("empty tracker triggers")
	}
	for i := 0; i < 8; i++ {
		tr.Record(true)
	}
	for i := 0; i < 4; i++ {
		tr.Record(false)
	}
	if !tr.ShouldBumpEpoch(0.75, 10) {
		t.Fatal("2/3 survival below 0.75 threshold not detected")
	}
	if tr.ShouldBumpEpoch(0.5, 10) {
		t.Fatal("2/3 survival false-triggered at 0.5 threshold")
	}
	if tr.Samples() != 12 {
		t.Fatalf("samples %d", tr.Samples())
	}
}
