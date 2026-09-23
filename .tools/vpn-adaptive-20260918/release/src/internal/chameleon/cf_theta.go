package chameleon

// cf_theta.go — Слой 8: стратегия — не геном, а распределение (+ бюджет утечки).
//
// Геном одноразовый: борд раздаёт не точки (даже MAP-Elites перечислим и
// выучиваем), а параметры распределения θ. Клиент выводит геном
// детерминированно из HKDF(session_seed ‖ epoch ‖ client_id) — по той же
// механике, что работает в DeriveSchedule (cf_schedule.go) и
// DeriveSessionSecret (cf_crypto.go). Ни одна конфигурация не повторяется
// дважды: цензор может выучить только носитель распределения, а не мишень.
// Оптимизация переезжает уровнем выше: ищется не лучший геном, а лучшее θ
// по агрегированным статистикам, которые федерирует слой 1 (cf_surrogate.go).
//
// Экспозиция — расходуемый ресурс: LeakBudget на эпоху, живые пробы
// выбираются по критерию «максимум ожидаемого information gain на единицу
// утечки» (оптимальный план эксперимента, а не «прогнать K финалистов»).

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"sort"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

// ThetaKind — маркер типа управляющего сообщения с параметрами распределения.
const ThetaKind = "citp-theta"

// Theta — параметры распределения геномов (то, что раздаёт борд).
// Диапазоны включительные [Lo,Hi]; единицы те же, что у Flavor.
type Theta struct {
	Kind       string  `json:"kind"` // ThetaKind
	V          int     `json:"v"`
	BaseMsLo   int     `json:"base_ms_lo"`
	BaseMsHi   int     `json:"base_ms_hi"`
	JitterLo   int     `json:"jitter_ms_lo"`
	JitterHi   int     `json:"jitter_ms_hi"`
	MinPadLo   int     `json:"min_pad_lo"`
	MinPadHi   int     `json:"min_pad_hi"`
	MaxPadLo   int     `json:"max_pad_lo"`
	MaxPadHi   int     `json:"max_pad_hi"`
	CanaryFrac float64 `json:"canary_frac"`      // доля популяции на канареечном под-распределении (слой 3)
	LeakBits   float64 `json:"leak_budget_bits"` // бюджет утечки на эпоху
}

// DefaultTheta — стартовое распределение: сетка диапазонов flavors.go,
// расширенная до непрерывных границ (динамический синтез FlavorByName("auto")
// — частный случай этой сетки).
func DefaultTheta() Theta {
	return Theta{
		Kind: ThetaKind, V: 1,
		BaseMsLo: 20, BaseMsHi: 280,
		JitterLo: 10, JitterHi: 200,
		MinPadLo: 60, MinPadHi: 260,
		MaxPadLo: 500, MaxPadHi: 1460,
		CanaryFrac: 0.05,
		LeakBits:   24,
	}
}

// Genome — конкретный одноразовый вариант клиента (точка из θ).
type Genome struct {
	Flavor      Flavor `json:"flavor"`
	Canary      bool   `json:"canary"`
	Epoch       uint64 `json:"epoch"`
	Fingerprint string `json:"fingerprint"` // короткий id для novelty-дистанций; не секрет
}

// Vec — нормированный параметрический вектор генома для дистанций (слой 2).
func (g Genome) Vec() []float64 {
	return []float64{
		float64(g.Flavor.Base) / float64(300*time.Millisecond),
		float64(g.Flavor.Jitter) / float64(300*time.Millisecond),
		float64(g.Flavor.MinPad) / 1500,
		float64(g.Flavor.MaxPad) / 1500,
	}
}

// DeriveGenome выводит одноразовый геном из HKDF(session_seed ‖ epoch ‖ client_id).
// Детерминировано: те же входы -> тот же геном; смена эпохи или клиента ->
// независимая точка из θ. Канареечная метка (слой 3) выводится тем же
// потоком: малая доля популяции попадает в заведомо более регулярный угол
// распределения (низкий джиттер — статистически заметнее, индикатор-приманка).
func DeriveGenome(th Theta, sessionSeed []byte, epoch uint64, clientID []byte) Genome {
	var eb [8]byte
	binary.BigEndian.PutUint64(eb[:], epoch)
	info := append([]byte("citp-theta-v1"), clientID...)
	out := make([]byte, 32)
	r := hkdf.New(sha256.New, sessionSeed, eb[:], info)
	_, _ = io.ReadFull(r, out)
	d := NewDRBG(out, "cf-theta-v1")

	rng := func(lo, hi int) int {
		if hi <= lo {
			return lo
		}
		return lo + d.Intn(hi-lo+1)
	}
	base := rng(th.BaseMsLo, th.BaseMsHi)
	jit := rng(th.JitterLo, th.JitterHi)
	minPad := rng(th.MinPadLo, th.MinPadHi)
	maxPad := rng(th.MaxPadLo, th.MaxPadHi)
	if maxPad < minPad+100 {
		maxPad = minPad + 100
	}

	canary := false
	if th.CanaryFrac > 0 {
		u := float64(d.Uint64()>>11) / float64(uint64(1)<<53) // [0,1)
		if u < th.CanaryFrac {
			canary = true
			if j2 := base / 4; j2 >= 1 && jit > j2 {
				jit = j2
			}
		}
	}

	g := Genome{
		Flavor: Flavor{
			Base:    time.Duration(base) * time.Millisecond,
			Jitter:  time.Duration(jit) * time.Millisecond,
			MinPad:  minPad,
			MaxPad:  maxPad,
			Comment: "theta-derived one-shot genome",
		},
		Canary: canary,
		Epoch:  epoch,
	}
	fp := sha256.Sum256(out[:16])
	g.Fingerprint = hex.EncodeToString(fp[:4])
	return g
}

// EncodeTheta / DecodeTheta — JSON-конверт для рассылки θ по борду.
func EncodeTheta(th Theta) ([]byte, error) { return json.Marshal(th) }

func DecodeTheta(b []byte) (Theta, error) {
	var th Theta
	if err := json.Unmarshal(b, &th); err != nil {
		return th, err
	}
	if err := ValidateTheta(th); err != nil {
		return th, err
	}
	return th, nil
}

// ControlMessageKind классифицирует управляющее сообщение борда: новые типы
// (theta, карта дорогих зон, grad-статистики) несут поле kind; node-hint
// (без kind) остаётся обратно совместимым со старыми клиентами.
func ControlMessageKind(msg []byte) string {
	var probe struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(msg, &probe); err == nil && probe.Kind != "" {
		return probe.Kind
	}
	return "node-hint"
}

// --- бюджет утечки на эпоху ---

// LeakBudget — расходуемый бюджет экспозиции (в битах информации о нас,
// которую получает цензор за эпоху). Потокобезопасен.
type LeakBudget struct {
	mu    sync.Mutex
	Epoch uint64  `json:"epoch"`
	Total float64 `json:"total"`
	Spent float64 `json:"spent"`
}

// NewLeakBudget preserves a zero exploration budget; invalid values fail closed.
func NewLeakBudget(epoch uint64, bits float64) *LeakBudget {
	if bits < 0 || math.IsNaN(bits) || math.IsInf(bits, 0) {
		bits = 0
	}
	return &LeakBudget{Epoch: epoch, Total: bits}
}

// TrySpend атомарно списывает bits; false — бюджет исчерпан (проба не идёт).
func (b *LeakBudget) TrySpend(bits float64) bool {
	if bits < 0 || math.IsNaN(bits) || math.IsInf(bits, 0) {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.Spent+bits > b.Total {
		return false
	}
	b.Spent += bits
	return true
}

// Remaining — остаток бюджета эпохи в битах.
func (b *LeakBudget) Remaining() float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return max(0, b.Total-b.Spent)
}

// SpentFrac — сколько мы уже «рассказали о себе» в этой эпохе ∈ [0,1].
func (b *LeakBudget) SpentFrac() float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.Total <= 0 {
		return 1
	}
	return min(1, max(0, b.Spent/b.Total))
}

// ProbeCandidate — кандидат на живую пробу: ожидаемый information gain и
// цена в битах утечки (оценки оператора/суррогата).
type ProbeCandidate struct {
	Name     string  `json:"name"`
	GainBits float64 `json:"gain_bits"`
	LeakBits float64 `json:"leak_bits"`
}

// SelectProbes — оптимальный план эксперимента: жадный выбор по убыванию
// gain/leak, пока хватает бюджета эпохи. Бюджет расходуется через TrySpend —
// повторный вызов в той же эпохе видит остаток.
func SelectProbes(cands []ProbeCandidate, budget *LeakBudget) []ProbeCandidate {
	sorted := append([]ProbeCandidate(nil), cands...)
	sort.SliceStable(sorted, func(i, j int) bool {
		ri := sorted[i].GainBits / math.Max(sorted[i].LeakBits, 1e-9)
		rj := sorted[j].GainBits / math.Max(sorted[j].LeakBits, 1e-9)
		return ri > rj
	})
	var out []ProbeCandidate
	for _, c := range sorted {
		if c.LeakBits <= 0 || c.GainBits <= 0 {
			continue
		}
		if budget.TrySpend(c.LeakBits) {
			out = append(out, c)
		}
	}
	return out
}
