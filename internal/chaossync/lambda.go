package chaossync

// lambda.go — целочисленная (Q16.48) оценка старшего показателя Ляпунова λ₁
// поля эпохи: Benettin-lite с ре-нормировкой касательного вектора СТЕПЕНЯМИ
// ДВОЙКИ. Назначение — хаос-пол DeriveFieldClass(FieldClassKeystream): поле
// принимается только если λ₁ ≥ KeystreamLambdaMin (schedule.go).
//
// КРИТИЧНО: оценка обязана быть БИТ-ИДЕНТИЧНА на Windows и Linux — по ней обе
// стороны независимо принимают/отбраковывают одно и то же поле эпохи. Поэтому
// здесь ноль float и ноль math.*: только целочисленная арифметика Q16.48.
//
// МЕТОД (телескопинг сдвигов): касательный вектор v проталкивается через
// Якобиан вдоль ТОЧНОЙ Q16.48-орбиты (тот же FieldParams.Step, что в проде);
// после каждого шага v масштабируется сдвигом на sh бит так, чтобы норма
// оставалась в [1/2, 2). Тогда точно:
//
//	λ₁ = lim (1/N)·ln‖J_{N-1}···J_0·v_0‖ = (1/N)·(ln2·Σ sh_k + ln‖v_N‖)
//
// т.е. накопленный логарифм роста телескопируется в СЧЁТЧИК СДВИГОВ плюс
// ограниченный граничный член log2‖v_N‖ — пошаговый логарифм не нужен вообще.
// (Первая версия накапливала ln нормы пошагово и давала смещение E[ln‖v_k‖]
// — выловлено калибровкой против float-эталона Э-A на ноде 2026-09-01;
// телескопинг совпал с эталоном до 4-го знака: 0.8380 vs 0.8379 бит/итер.)
//
// Отличие от лабораторного cmd/chaos-metrics (публикационный спектр на
// float64-касательных): здесь один касательный вектор и ~2^13 итераций —
// грубее, но с большим запасом различает квазипериодику (прод-поля Э-A:
// λ₁≈±3e-6) и хаос (зона ε≲0.05: λ₁≈0.7-0.95 бит/итер). Калибровка против
// эталонов Э-A — гейт в fieldclass_test.go.

// isqrt64 — floor(√x), поразрядный метод. Детерминирован на всех платформах.
func isqrt64(x uint64) uint64 {
	var r uint64
	bit := uint64(1) << 62
	for bit > x {
		bit >>= 2
	}
	for bit != 0 {
		if x >= r+bit {
			x -= r + bit
			r = (r >> 1) + bit
		} else {
			r >>= 1
		}
		bit >>= 2
	}
	return r
}

// divFxp — (a·2^48)/b со знаком, b > 0. Делимое |a|·2^48 (128 бит) делится
// длинной схемой shift-subtract: 128 итераций, инвариант rem < den < 2^63 —
// переполнения нет, результат (floor по модулю, затем знак) одинаков везде.
// Переполнение частного (> 2^63-1) — насыщение; достижимо только на
// патологически сжимающих полях, где вывод «далеко от хаоса» уже сделан.
func divFxp(a, b Fxp) Fxp {
	if b <= 0 {
		panic("chaossync: divFxp с неположительным делителем") // ошибка вызывающего
	}
	neg := a < 0
	ua := uint64(int64(a))
	if neg {
		ua = uint64(-int64(a))
	}
	den := uint64(int64(b))
	hi, lo := ua>>16, ua<<48 // делимое = ua·2^48
	var quo uint64
	var rem uint64
	overflow := false
	for i := 0; i < 128; i++ {
		bit := (hi >> 63) & 1
		hi = (hi << 1) | (lo >> 63)
		lo <<= 1
		rem = (rem << 1) | bit
		q := uint64(0)
		if rem >= den {
			rem -= den
			q = 1
		}
		if i < 64 {
			if q != 0 {
				overflow = true
			}
		} else {
			quo = (quo << 1) | q
		}
	}
	if overflow || quo > (uint64(1)<<63)-1 {
		quo = (uint64(1) << 63) - 1
	}
	if neg {
		return Fxp(-int64(quo))
	}
	return Fxp(int64(quo))
}

// atanhSeries — 2·(z + z³/3 + z⁵/5 + …) в Q16.48 при |z| ≤ 1/3 (область после
// редукции диапазона ln). Остановка — по нулевому ВКЛАДУ члена: при floor-
// усечении малый отрицательный член «залипал» бы на -1 (бесконечный цикл,
// выловлено первым прогоном на ноде 2026-09-01); вклад же обнуляется, а члены
// дальше только убывают по модулю → хвост гарантированно нулевой.
func atanhSeries(z Fxp) Fxp {
	z2 := z.Mul(z)
	term := z
	sum := Fxp(0)
	for k := int64(1); ; k += 2 {
		c := int64(term) / k
		if c == 0 {
			break
		}
		sum = sum.Add(Fxp(c))
		term = term.Mul(z2)
	}
	return sum.Add(sum)
}

// ln2Fxp — ln 2 в Q16.48: тот же ряд atanh при z = 1/3 (константа вычислена,
// а не записана — меньше места для расхождения).
var ln2Fxp = atanhSeries(divFxp(One, FromInt(3)))

// sqrt2Fxp — √2 в Q16.48 через целочисленный isqrt (pivot редукции ln).
var sqrt2Fxp = Fxp(int64(isqrt64(uint64(2)<<48)) << 24)

// lnFxp — натуральный логарифм x > 0 в Q16.48: редукция x = m·2^k,
// m ∈ [√2/2, √2), затем ряд atanh. Детерминирован. Используется только для
// граничного члена log2‖v_N‖ (один раз на прогон).
func lnFxp(x Fxp) Fxp {
	if x <= 0 {
		panic("chaossync: lnFxp неположительного аргумента") // ошибка вызывающего
	}
	k := int64(0)
	m := x
	for m >= sqrt2Fxp {
		m = Fxp(int64(m) >> 1)
		k++
	}
	halfSqrt2 := Fxp(int64(sqrt2Fxp) >> 1)
	for m < halfSqrt2 {
		m = Fxp(int64(m) << 1)
		k--
	}
	z := divFxp(m.Sub(One), m.Add(One))
	return atanhSeries(z).Add(ln2Fxp.Mul(FromInt(k)))
}

// lambdaMinIters — нижняя крышка длины прогона (статистическая осмысленность).
const lambdaMinIters = 1024

// lambdaNoChaos — детерминированный ответ «далеко от хаоса» при вырождении
// касательного вектора (мера нуля; защита от деления на ноль).
var lambdaNoChaos = FromInt(-1024)

// EstimateLambdaMax — Benettin-lite оценка старшего показателя Ляпунова поля p
// (бит/итерация, Q16.48). Оценка — функция ТОЛЬКО поля и iters: стартовая
// точка орбиты (x_i = (i+1)/(Sites+1)) и начальный касательный вектор e_0 —
// фиксированные константы. Вся арифметика целочисленная → значение бит-
// идентично на Windows и Linux (гейт выбора поля).
//
// Разрешение оценки 1/measure бит/итерации (~1.5e-4 при 8192) — для порога
// KeystreamLambdaMin = 0.5 против λ₁≈0 (квазипериодика) запас на 3+ порядка.
// Стоимость: < 1 мкс/итерацию на CPU ноды (8192 итерации ≈ 3-7 мс/кандидат —
// замер 2026-09-01), в бюджете ~50 мс/поле с большим запасом.
func EstimateLambdaMax(p *FieldParams, iters int) Fxp {
	if iters < lambdaMinIters {
		iters = lambdaMinIters
	}
	transient := iters / 5
	measure := iters - transient

	var x [Sites]Fxp
	den := FromInt(int64(Sites) + 1)
	for i := 0; i < Sites; i++ {
		x[i] = divFxp(FromInt(int64(i+1)), den)
	}
	var v [Sites]Fxp
	v[0] = One

	oneME := One.Sub(p.Eps1).Sub(p.Eps2) // диагональный вес M[i][i] = 1−ε1−ε2
	quarter := Fxp(oneRaw >> 2)
	four := FromInt(4)

	var sumSh int64 // Σ показателей сдвига = накопленный рост в битах
	for step := 0; step < iters; step++ {
		p.Step(&x)
		// Якобиан гладкой карты: J[i][j] = M[i][j]·μ_j·(1−2x_j); ненулевые
		// столбцы строки i: j ∈ {i, Prev[i], Next[i]}.
		var df [Sites]Fxp
		for j := 0; j < Sites; j++ {
			df[j] = p.Mu[j].Mul(One.Sub(x[j]).Sub(x[j]))
		}
		var nv [Sites]Fxp
		for i := 0; i < Sites; i++ {
			nv[i] = oneME.Mul(df[i]).Mul(v[i]).
				Add(p.Eps1.Mul(df[p.Prev[i]]).Mul(v[p.Prev[i]])).
				Add(p.Eps2.Mul(df[p.Next[i]]).Mul(v[p.Next[i]]))
		}
		var norm2 Fxp
		for i := 0; i < Sites; i++ {
			norm2 = norm2.Add(nv[i].Mul(nv[i]))
		}
		if norm2 <= 0 {
			return lambdaNoChaos
		}
		// Ре-нормировка к norm2 ∈ [1/4, 4) (норма ∈ [1/2, 2)) сдвигами.
		sh := int64(0)
		for norm2 >= four {
			for i := 0; i < Sites; i++ {
				nv[i] = Fxp(int64(nv[i]) >> 1)
			}
			norm2 = Fxp(int64(norm2) >> 2)
			sh++
		}
		for norm2 < quarter {
			for i := 0; i < Sites; i++ {
				nv[i] = Fxp(int64(nv[i]) << 1)
			}
			norm2 = Fxp(int64(norm2) << 2)
			sh--
		}
		if step >= transient {
			sumSh += sh
		}
		v = nv
	}
	// λ₁ = (Σ sh + log2‖v_end‖) / measure  [бит/итерация]; граничный член
	// |log2‖v_end‖| < 1 — на порог не влияет, но учитывается для точности.
	var norm2e Fxp
	for i := 0; i < Sites; i++ {
		norm2e = norm2e.Add(v[i].Mul(v[i]))
	}
	if norm2e <= 0 {
		return lambdaNoChaos
	}
	endNorm := Fxp(int64(isqrt64(uint64(int64(norm2e)))) << 24)
	log2end := divFxp(lnFxp(endNorm), ln2Fxp)
	// Насыщение счётчика против переполнения FromInt на патологически
	// сжимающих полях (на реальных недостижимо: |λ₁| ≲ 1 бит/итер; предел
	// ±30000 сдвигов = ±4.6 бит/итер — далеко за зоной отбора). Одинаково на
	// всех платформах → детерминизм сохранён даже в патологии.
	if sumSh > 30000 {
		sumSh = 30000
	}
	if sumSh < -30000 {
		sumSh = -30000
	}
	return divFxp(FromInt(sumSh).Add(log2end), FromInt(int64(measure)))
}
