package chameleon

// cf_surrogate.go — Слои 1–3: федеративная суррогат-модель цензора,
// полиморфизм популяции, канарейки-ловушки.
//
// Слой 1 (GAN-контур): онлайн-логистическая регрессия — обучаемая копия
// решающей границы DPI. Обучается на (признаки -> вердикт) из
// netprofile.jsonl — своих и экзогенных (слой 7), взвешенных WeightedObs.
// Генетический поиск прогоняется против суррогата офлайн (миллионы оценок
// бесплатно); живьём — только финалисты в пределах leak budget (слой 8).
// Федерация: клиенты сливают через борд только градиентные статистики
// (GradStats) — сырые признаки/трафик клиента не покидают.
//
// Слой 2 (полиморфизм): novelty-член в fitness — «живучий И непохожий на
// остальных». Успешная стратегия не создаёт единой сигнатуры: носитель —
// облако точек из θ (слой 8), а не один геном.
//
// Слой 3 (канарейки): канареечные геномы помечаются в DeriveGenome; падение
// их выживаемости ниже порога при достаточной выборке = ТСПУ обновила
// правила -> автоматический epoch bump и переобучение суррогата РАНЬШЕ,
// чем блок докатится до основной популяции.

import (
	"encoding/json"
	"math"
	"sort"
	"sync"
	"time"
)

// GradStatsKind — маркер типа сообщения борда с федеративными статистиками.
const GradStatsKind = "citp-gradstats"

// Surrogate — лёгкий дискриминатор (логистическая регрессия, онлайн-SGD,
// L2-регуляризация). Обучаемая копия решающей границы DPI.
type Surrogate struct {
	W  []float64 `json:"w"`
	B  float64   `json:"b"`
	N  uint64    `json:"n"` // сколько наблюдений съедено (доверие/калибровка)
	mu sync.Mutex
}

// NewSurrogate — модель размерности dim (см. ObsFeatures: 5 признаков).
func NewSurrogate(dim int) *Surrogate {
	if dim <= 0 {
		dim = 5
	}
	return &Surrogate{W: make([]float64, dim)}
}

func sigmoid(z float64) float64 { return 1 / (1 + math.Exp(-z)) }

func (s *Surrogate) predictNoLock(x []float64) float64 {
	z := s.B
	for i := 0; i < len(s.W) && i < len(x); i++ {
		z += s.W[i] * x[i]
	}
	return sigmoid(z)
}

// Predict — P(блок | x) по текущей копии границы.
func (s *Surrogate) Predict(x []float64) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.predictNoLock(x)
}

// Learn — один шаг SGD по взвешенному наблюдению; w — вес (WeightedObs:
// доверие к источнику * recency-забывание, слой 7).
func (s *Surrogate) Learn(x []float64, y, w, lr float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := (s.predictNoLock(x) - y) * w
	for i := range s.W {
		if i < len(x) {
			s.W[i] -= lr * (err*x[i] + 1e-4*s.W[i])
		}
	}
	s.B -= lr * err
	s.N++
}

// TrainFromObservations — один проход по журналу наблюдений (own+exo) с
// весами источника и забыванием. Возвращает число съеденных записей.
func (s *Surrogate) TrainFromObservations(obs []NetObservation, now time.Time, halfLife time.Duration, lr float64) int {
	n := 0
	for _, o := range obs {
		w := WeightedObs(o, now, halfLife)
		y := 0.0
		if o.HasDPI {
			y = 1
		}
		s.Learn(ObsFeatures(o), y, w, lr)
		n++
	}
	return n
}

// ObsFeatures — признаковый вектор наблюдения для суррогата:
// [dpi, dns_hijack, tcp_reset, tls_interf, http_block_page] как 0/1.
func ObsFeatures(o NetObservation) []float64 {
	b2f := func(b bool) float64 {
		if b {
			return 1
		}
		return 0
	}
	return []float64{b2f(o.HasDPI), b2f(o.DNSHijack), b2f(o.TCPReset), b2f(o.TLSInterf), b2f(o.HTTPBlockPage)}
}

// GradStats — федеративные sufficient statistics: сумма градиентов клиента.
// Безопасны для борда: агрегат без сырых признаков. Kind — для
// классификации сообщений борда (ControlMessageKind).
type GradStats struct {
	Kind string    `json:"kind,omitempty"`
	GW   []float64 `json:"gw"`
	GB   float64   `json:"gb"`
	N    uint64    `json:"n"`
}

// StatsFrom вычисляет градиентную статистику клиента по его наблюдениям
// (локально; на борд уходит только агрегат).
func (s *Surrogate) StatsFrom(xs [][]float64, ys, ws []float64) GradStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := GradStats{Kind: GradStatsKind, GW: make([]float64, len(s.W))}
	for k := range xs {
		w := 1.0
		if k < len(ws) {
			w = ws[k]
		}
		y := 0.0
		if k < len(ys) {
			y = ys[k]
		}
		err := (s.predictNoLock(xs[k]) - y) * w
		for i := range g.GW {
			if i < len(xs[k]) {
				g.GW[i] += err * xs[k][i]
			}
		}
		g.GB += err
		g.N++
	}
	return g
}

// MergeGradStats — коммутативное слияние статистик клиентов (на борде или у
// клиента-агрегатора).
func MergeGradStats(a, b GradStats) GradStats {
	n := len(a.GW)
	if len(b.GW) > n {
		n = len(b.GW)
	}
	out := GradStats{Kind: GradStatsKind, GW: make([]float64, n), GB: a.GB + b.GB, N: a.N + b.N}
	for i := range out.GW {
		if i < len(a.GW) {
			out.GW[i] += a.GW[i]
		}
		if i < len(b.GW) {
			out.GW[i] += b.GW[i]
		}
	}
	return out
}

// ApplyStats — шаг по агрегированному градиенту (усреднённому по N).
func (s *Surrogate) ApplyStats(g GradStats, lr float64) {
	if g.N == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	inv := 1 / float64(g.N)
	for i := range s.W {
		if i < len(g.GW) {
			s.W[i] -= lr * (g.GW[i]*inv + 1e-4*s.W[i])
		}
	}
	s.B -= lr * g.GB * inv
	s.N += g.N
}

// Encode / Decode GradStats для борда.
func (g GradStats) Encode() ([]byte, error) { return json.Marshal(g) }

func DecodeGradStats(b []byte) (GradStats, error) {
	var g GradStats
	if err := json.Unmarshal(b, &g); err != nil {
		return g, err
	}
	return g, nil
}

// --- слой 2: полиморфизм ---

// GenomeDistance — евклидово расстояние в нормированном пространстве
// параметров генома (Vec).
func GenomeDistance(a, b Genome) float64 {
	va, vb := a.Vec(), b.Vec()
	d := 0.0
	for i := range va {
		df := va[i] - vb[i]
		d += df * df
	}
	return math.Sqrt(d)
}

// NoveltyScore ∈ (0,1]: среднее расстояние до k ближайших соседей,
// нормированное на диаметр пространства. Одинокий геном получает 1.
// Это второй член fitness: «живучий И непохожий на остальных».
func NoveltyScore(g Genome, pop []Genome, k int) float64 {
	if len(pop) == 0 {
		return 1
	}
	if k <= 0 {
		k = 3
	}
	ds := make([]float64, 0, len(pop))
	for _, p := range pop {
		if p.Fingerprint == g.Fingerprint {
			continue // не сравниваем геном с самим собой
		}
		ds = append(ds, GenomeDistance(g, p))
	}
	if len(ds) == 0 {
		return 1
	}
	sort.Float64s(ds)
	if k > len(ds) {
		k = len(ds)
	}
	s := 0.0
	for i := 0; i < k; i++ {
		s += ds[i]
	}
	return s / float64(k) / math.Sqrt(float64(len(g.Vec())))
}

// --- слой 3: канарейки ---

// CanaryTracker — выживаемость канареечных геномов в AS/эпохе. Канарейки —
// заведомо чуть более заметные стратегии-приманки (малая доля популяции,
// см. Theta.CanaryFrac); их массовая гибель — упреждающий сигнал обновления
// правил цензора, до урона по основной популяции.
type CanaryTracker struct {
	mu    sync.Mutex
	alive int
	dead  int
}

// Record фиксирует исход канареечной сессии.
func (t *CanaryTracker) Record(survived bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if survived {
		t.alive++
	} else {
		t.dead++
	}
}

// Survival — текущая выживаемость канареек; пустая выборка = 1 (нет сигнала).
func (t *CanaryTracker) Survival() float64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := t.alive + t.dead
	if n == 0 {
		return 1
	}
	return float64(t.alive) / float64(n)
}

// Samples — объём накопленной выборки.
func (t *CanaryTracker) Samples() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.alive + t.dead
}

// ShouldBumpEpoch — true, когда выборка достаточна и выживаемость канареек
// упала ниже threshold: сигнал, что ТСПУ обновила правила -> epoch bump и
// переобучение суррогата до того, как блок докатится до основной массы.
func (t *CanaryTracker) ShouldBumpEpoch(threshold float64, minSamples int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := t.alive + t.dead
	if n < minSamples || n == 0 {
		return false
	}
	return float64(t.alive)/float64(n) < threshold
}
