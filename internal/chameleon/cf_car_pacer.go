package chameleon

// cf_car_pacer.go — Этап A3: случайный пейсинг чтения CAR-канала.
//
// Прежний ритм — фиксированные 150 мс/бит — наш собственный детектор
// query-cadence ловит мгновенно (коэффициент вариации CV < 0.15). Теперь
// межоконные паузы логнормальны (та же идея, что в cover.go): медиана 150 мс,
// sigma 0.6 -> CV ≈ 0.66, с запасом выше порога детектора, при сопоставимой
// средней стоимости чтения. Редкие длинные хвосты логнормали имитируют
// «задумавшегося» пользователя.

import (
	"math"
	"math/rand/v2"
	"time"
)

// CARPacer выдаёт случайные паузы между чтениями окон CAR-канала.
// Не потокобезопасен: один читатель — один пейсер.
type CARPacer struct {
	median time.Duration
	sigma  float64
	rng    *rand.Rand
}

// NewCARPacer — логнормальный пейсер с заданной медианой и sigma
// (sigma <= 0 вырождается в фиксированную паузу — режим для отладки).
func NewCARPacer(median time.Duration, sigma float64) *CARPacer {
	now := uint64(time.Now().UnixNano())
	return &CARPacer{
		median: median,
		sigma:  sigma,
		rng:    rand.New(rand.NewPCG(now, now^0x9E3779B97F4A7C15)),
	}
}

// newCARPacerSeeded — детерминированный пейсер для тестов.
func newCARPacerSeeded(median time.Duration, sigma float64, seed uint64) *CARPacer {
	return &CARPacer{
		median: median,
		sigma:  sigma,
		rng:    rand.New(rand.NewPCG(seed, seed^0xD1B54A32D192ED03)),
	}
}

// Next возвращает следующую паузу: median * exp(sigma * N(0,1)), усечённую в
// [1 мс, 30 с] (усечение хвоста не даёт чтению умереть на реальном ТСПУ с
// долгими вердиктами).
func (p *CARPacer) Next() time.Duration {
	if p == nil || p.median <= 0 {
		return 0
	}
	if p.sigma <= 0 {
		return p.median
	}
	d := float64(p.median) * math.Exp(p.sigma*p.rng.NormFloat64())
	const minD = float64(time.Millisecond)
	const maxD = float64(30 * time.Second)
	if d < minD {
		d = minD
	}
	if d > maxD {
		d = maxD
	}
	return time.Duration(d)
}

// Pause спит одну случайную паузу.
func (p *CARPacer) Pause() {
	if d := p.Next(); d > 0 {
		time.Sleep(d)
	}
}
