package chameleon

// cf_collateral.go — Слой 6 (флагман): оптимизация под цену ошибки цензора.
//
// Цензор — не детектор, а оптимизатор с бюджетом ошибок: он минимизирует FN
// при жёстком ограничении на FP (сбить Сбер/Госуслуги/эквайринг = операторный
// инцидент). Значит, у любого нашего кандидат-профиля есть измеримая
// величина — сколько легитимного трафика попадёт под минимальное правило,
// отделяющее нас от фона. Мы её вычисляем и максимизируем: не свою
// скрытность, а ЕГО цену ошибки.
//
// Метрика: перекрытие гистограмм (bin-overlap) и MMD между flow-профилем
// кандидата и референсными профилями «дорогих» сервисов. Референсы
// синтезируются из стоящих в коде Flavor'ов (flavors.go) — те же ритмы,
// что использует шейпер. Борд раздаёт не только область живучих профилей,
// но и карту дорогих зон (CollateralMap) для конкретной AS.
//
// ГРАНИЦА (зафиксирована владельцем проекта): легитимна только СОБСТВЕННАЯ
// мимикрия — мы формируем свой трафик так, чтобы он статистически вкладывался
// в защищённые классы. Намеренное отравление обучающих данных цензора, чтобы
// он блокировал реальных пользователей банка, здесь НЕ реализуется и не
// проектируется: это перекладывание вреда на третьих лиц и провокация
// перехода оператора к белым спискам.

import (
	"encoding/json"
	"errors"
	"math"
	"time"
)

// Разметка гистограмм: 16 бин размера по 100 байт (0..1600, MTU-потолок),
// 16 бин интервалов по 32 мс (0..512 мс — покрывает все Flavor'ы).
const (
	flowHistBins  = 16
	flowSizeBinW  = 100.0
	flowIATBinWms = 32.0
)

// FlowProfile — нормированное гистограммное представление потока: то, что
// видит DPI (длины и интервалы), без содержимого. Scalar — компактный вектор
// для MMD: [meanSize/1600, cvSize, meanIAT/512, cvIAT, cbr].
type FlowProfile struct {
	Name     string    `json:"name,omitempty"`
	SizeHist []float64 `json:"size_hist"`
	IATHist  []float64 `json:"iat_hist"`
	CBR      float64   `json:"cbr"`
	Scalar   []float64 `json:"scalar"`
}

// FlowProfileFromFlavor синтезирует референсный профиль из параметров
// Flavor'а детерминированно: размеры ~ uniform[MinPad,MaxPad], интервалы ~
// Base + uniform[0,Jitter]. Без RNG — одинаковый вход даёт байт-в-байт
// одинаковый профиль на всех сторонах.
func FlowProfileFromFlavor(name string, f Flavor) FlowProfile {
	sizes := make([]float64, flowHistBins)
	lo, hi := float64(f.MinPad), float64(f.MaxPad)
	if hi <= lo {
		hi = lo + 1
	}
	for b := 0; b < flowHistBins; b++ {
		blo, bhi := float64(b)*flowSizeBinW, float64(b+1)*flowSizeBinW
		ov := math.Min(hi, bhi) - math.Max(lo, blo)
		if ov > 0 {
			sizes[b] = ov / (hi - lo)
		}
	}
	iat := make([]float64, flowHistBins)
	base := float64(f.Base) / float64(time.Millisecond)
	jit := float64(f.Jitter) / float64(time.Millisecond)
	if jit < 1 {
		jit = 1
	}
	for b := 0; b < flowHistBins; b++ {
		blo, bhi := float64(b)*flowIATBinWms, float64(b+1)*flowIATBinWms
		ov := math.Min(base+jit, bhi) - math.Max(base, blo)
		if ov > 0 {
			iat[b] = ov / jit
		}
	}
	meanSize := (lo + hi) / 2
	cvSize := (hi - lo) / math.Sqrt(12) / math.Max(meanSize, 1) // cv uniform
	meanIAT := base + jit/2
	cvIAT := jit / math.Sqrt(12) / math.Max(meanIAT, 1)
	cbr := math.Max(0, 1-cvIAT)
	return FlowProfile{
		Name:     name,
		SizeHist: normalizeHist(sizes),
		IATHist:  normalizeHist(iat),
		CBR:      cbr,
		Scalar:   []float64{meanSize / 1600, cvSize, meanIAT / 512, cvIAT, cbr},
	}
}

// FlowProfileFromSamples строит профиль из наблюденных выборок (выход
// cham-flowstats / живой замер сессии).
func FlowProfileFromSamples(name string, sizes []int, iatMs []float64) FlowProfile {
	sh := make([]float64, flowHistBins)
	var sumS, sumSqS float64
	for _, s := range sizes {
		b := int(float64(s) / flowSizeBinW)
		if b >= flowHistBins {
			b = flowHistBins - 1
		}
		if b < 0 {
			b = 0
		}
		sh[b]++
		sumS += float64(s)
	}
	ih := make([]float64, flowHistBins)
	var sumI, sumSqI float64
	for _, v := range iatMs {
		b := int(v / flowIATBinWms)
		if b >= flowHistBins {
			b = flowHistBins - 1
		}
		if b < 0 {
			b = 0
		}
		ih[b]++
		sumI += v
	}
	n := math.Max(float64(len(sizes)), 1)
	meanS := sumS / n
	for _, s := range sizes {
		d := float64(s) - meanS
		sumSqS += d * d
	}
	m := math.Max(float64(len(iatMs)), 1)
	meanI := sumI / m
	for _, v := range iatMs {
		d := v - meanI
		sumSqI += d * d
	}
	cvS := 0.0
	if meanS > 0 {
		cvS = math.Sqrt(sumSqS/n) / meanS
	}
	cvI := 0.0
	if meanI > 0 {
		cvI = math.Sqrt(sumSqI/m) / meanI
	}
	cbr := math.Max(0, 1-cvI)
	return FlowProfile{
		Name:     name,
		SizeHist: normalizeHist(sh),
		IATHist:  normalizeHist(ih),
		CBR:      cbr,
		Scalar:   []float64{meanS / 1600, cvS, meanI / 512, cvI, cbr},
	}
}

func normalizeHist(h []float64) []float64 {
	sum := 0.0
	for _, v := range h {
		sum += v
	}
	if sum <= 0 {
		return h
	}
	out := make([]float64, len(h))
	for i, v := range h {
		out[i] = v / sum
	}
	return out
}

// HistogramIntersection — пересечение нормированных гистограмм ∈ [0,1]:
// доля вероятностной массы, которую правило «всё в этих бинах» срезает у
// ОБОИХ распределений одновременно. Это и есть нижняя оценка цены ошибки.
func HistogramIntersection(a, b []float64) float64 {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	s := 0.0
	for i := 0; i < n; i++ {
		s += math.Min(a[i], b[i])
	}
	if s < 0 {
		return 0
	}
	if s > 1 {
		return 1
	}
	return s
}

// MMD2 — смещённая оценка квадрата Maximum Mean Discrepancy с RBF-ядром по
// скалярным векторам двух наборов профилей (диагностика расстояния между
// распределениями; 0 = неразличимы на этом ядре).
func MMD2(xs, ys [][]float64, gamma float64) float64 {
	if len(xs) == 0 || len(ys) == 0 {
		return 0
	}
	if gamma <= 0 {
		gamma = 1.0
	}
	k := func(a, b []float64) float64 {
		d := 0.0
		for i := 0; i < len(a) && i < len(b); i++ {
			df := a[i] - b[i]
			d += df * df
		}
		return math.Exp(-gamma * d)
	}
	sum := func(as, bs [][]float64) float64 {
		t := 0.0
		for _, a := range as {
			for _, b := range bs {
				t += k(a, b)
			}
		}
		return t
	}
	nx, ny := float64(len(xs)), float64(len(ys))
	v := sum(xs, xs)/(nx*nx) + sum(ys, ys)/(ny*ny) - 2*sum(xs, ys)/(nx*ny)
	if v < 0 {
		return 0
	}
	return v
}

// ReferenceClass — защищённый класс трафика: референс-профиль и цена ошибки
// (доля «недопустимости» его блокировки для оператора; 1 = операторный
// инцидент). CostWeight задаётся оператором, не измеряется нами.
type ReferenceClass struct {
	Name       string      `json:"name"`
	Profile    FlowProfile `json:"profile"`
	CostWeight float64     `json:"cost_weight"`
}

// DefaultProtectedClasses — референсы «дорогих» сервисов из стоящего в коде
// пула Flavor'ов: банк/госуслуги/эквайринг-подобный API-трафик (cost=1.0),
// маркетплейсы/почта/поиск (0.7), видео (0.4 — терпимо к деградации).
// Веса — стартовый приор оператора; уточняются картой дорогих зон по AS.
func DefaultProtectedClasses() []ReferenceClass {
	mk := func(name string, cost float64) ReferenceClass {
		return ReferenceClass{Name: name, Profile: FlowProfileFromFlavor(name, Flavors[name]), CostWeight: cost}
	}
	return []ReferenceClass{
		mk("sber", 1.0),
		mk("gosuslugi", 1.0),
		mk("wb-ozon", 0.7),
		mk("mail", 0.7),
		mk("yandex", 0.7),
		mk("vk-feed", 0.5),
		mk("vk-video", 0.4),
		mk("rutube", 0.4),
		mk("kinopoisk", 0.4),
	}
}

// LeverageScore — collateral leverage кандидата ∈ [0,1]: максимум по
// защищённым классам из (цена класса * вложенность кандидата в класс).
// Вложенность = среднее пересечений гистограмм размеров и интервалов,
// домноженное на RBF-близость скаляров (штраф за сдвинутые моменты).
func LeverageScore(cand FlowProfile, refs []ReferenceClass) float64 {
	best := 0.0
	for _, r := range refs {
		ov := 0.5*HistogramIntersection(cand.SizeHist, r.Profile.SizeHist) +
			0.5*HistogramIntersection(cand.IATHist, r.Profile.IATHist)
		sim := 1.0
		if len(cand.Scalar) > 0 && len(r.Profile.Scalar) > 0 {
			sim = math.Exp(-MMD2([][]float64{cand.Scalar}, [][]float64{r.Profile.Scalar}, 4.0))
		}
		l := r.CostWeight * ov * sim
		if l > best {
			best = l
		}
	}
	if best > 1 {
		best = 1
	}
	return best
}

// --- карта дорогих зон (раздаётся бордом) ---

// CollateralKind — маркер типа управляющего сообщения с картой дорогих зон.
const CollateralKind = "citp-collateral-map"

// CollateralZone — одна дорогая зона в конкретной AS.
type CollateralZone struct {
	Class    string      `json:"class"`
	Cost     float64     `json:"cost"`
	Profile  FlowProfile `json:"profile"`
	Leverage float64     `json:"leverage"` // достигнутый leverage лучшего кандидата
}

// CollateralMap — карта дорогих зон для AS: что цензор не может себе
// позволить сломать и насколько наши кандидаты туда вложены.
type CollateralMap struct {
	Kind       string           `json:"kind"` // CollateralKind
	V          int              `json:"v"`
	AS         string           `json:"as"`
	MeasuredAt time.Time        `json:"measured_at"`
	Zones      []CollateralZone `json:"zones"`
}

// NewCollateralMap собирает карту для AS: leverage каждой зоны — лучший
// результат по переданным кандидатам (может быть пусто — тогда 0).
func NewCollateralMap(as string, cands []FlowProfile) CollateralMap {
	m := CollateralMap{Kind: CollateralKind, V: 1, AS: as, MeasuredAt: time.Now().UTC()}
	for _, r := range DefaultProtectedClasses() {
		z := CollateralZone{Class: r.Name, Cost: r.CostWeight, Profile: r.Profile}
		best := 0.0
		for _, c := range cands {
			if l := LeverageScore(c, []ReferenceClass{r}); l > best {
				best = l
			}
		}
		z.Leverage = best
		m.Zones = append(m.Zones, z)
	}
	return m
}

// EncodeCollateralMap / DecodeCollateralMap — JSON-конверт для борда.
func EncodeCollateralMap(m CollateralMap) ([]byte, error) { return json.Marshal(m) }

func DecodeCollateralMap(b []byte) (CollateralMap, error) {
	var m CollateralMap
	if err := json.Unmarshal(b, &m); err != nil {
		return m, err
	}
	if m.Kind != CollateralKind {
		return m, errors.New("cf-collateral: not a collateral map")
	}
	return m, nil
}

// --- интеграция в fitness (фаза 1: третий член в двухчленный fitness) ---

// FitnessTerms — члены целевой функции: выживаемость, непохожесть на своих
// (слой 2), похожесть на фон и collateral leverage (слой 6). Все ∈ [0,1].
type FitnessTerms struct {
	Survival   float64 `json:"survival"`
	Novelty    float64 `json:"novelty"`
	Background float64 `json:"background"`
	Leverage   float64 `json:"leverage"`
}

// FitnessWeights — веса членов. Дефолт держит leverage значимым, но не
// доминирующим: структурная защита не отменяет базовой вложенности в фон.
type FitnessWeights struct {
	Survival   float64 `json:"survival"`
	Novelty    float64 `json:"novelty"`
	Background float64 `json:"background"`
	Leverage   float64 `json:"leverage"`
}

// DefaultFitnessWeights — стартовые веса слоя 6 в общем fitness.
func DefaultFitnessWeights() FitnessWeights {
	return FitnessWeights{Survival: 0.45, Novelty: 0.15, Background: 0.2, Leverage: 0.2}
}

// Score сворачивает члены в скаляр (линейная свёртка; сумма весов
// нормируется, чтобы Score оставался в [0,1] при членах из [0,1]).
func (t FitnessTerms) Score(w FitnessWeights) float64 {
	tot := w.Survival + w.Novelty + w.Background + w.Leverage
	if tot <= 0 {
		return 0
	}
	s := t.Survival*w.Survival + t.Novelty*w.Novelty + t.Background*w.Background + t.Leverage*w.Leverage
	return s / tot
}

// --- проводной формат карты для борда (слой 6) ---

// CollateralZoneSlim — зона без профиля: референсные профили детерминированно
// восстанавливаются клиентом из DefaultProtectedClasses (те же Flavors),
// по сети не передаются — карта помещается в один кадр борда.
type CollateralZoneSlim struct {
	Class    string  `json:"class"`
	Cost     float64 `json:"cost"`
	Leverage float64 `json:"leverage"`
}

// CollateralMapSlim — проводной формат CollateralMap для рассылки бордом.
type CollateralMapSlim struct {
	Kind       string               `json:"kind"` // CollateralKind
	V          int                  `json:"v"`
	AS         string               `json:"as"`
	MeasuredAt time.Time            `json:"measured_at"`
	Zones      []CollateralZoneSlim `json:"zones"`
}

// Slim отбрасывает профили зон для проводного формата.
func (m CollateralMap) Slim() CollateralMapSlim {
	s := CollateralMapSlim{Kind: m.Kind, V: m.V, AS: m.AS, MeasuredAt: m.MeasuredAt}
	for _, z := range m.Zones {
		s.Zones = append(s.Zones, CollateralZoneSlim{Class: z.Class, Cost: z.Cost, Leverage: z.Leverage})
	}
	return s
}

// EncodeCollateralMapSlim кодирует проводной формат карты для борда.
func EncodeCollateralMapSlim(s CollateralMapSlim) ([]byte, error) { return json.Marshal(s) }
