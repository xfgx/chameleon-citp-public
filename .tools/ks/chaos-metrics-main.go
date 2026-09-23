// chaos-metrics — измерительная лаборатория ядра chaossync (Э-A/Э-B/Э-C).
//
// Методическая честность: базовая динамика — ТОЧНЫЙ продакшн-код Q16.48
// (FieldParams.Step, гейт Э1 не касаемся). Касательный анализ (спектр
// Ляпунова) — float64 поверх точной траектории: показатели — статистические
// величины гладкой карты на параметрах эпохи (теневой аргумент), на проводе
// это нигде не используется. Э-B гоняется через РЕАЛЬНЫЙ провод протокола
// (Step → возмущение → Quantize16 → Dequantize16 → ObserverStep). Э-C —
// символьная статистика свободной траектории + PoC HGO-контроля одного
// логистического сайта (μ — фактический параметр драйв-сайта поля эпохи).
//
// Ничего не уходит в сеть; чистое измерение на RU-ноде.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"time"

	"chameleon/internal/chaossync"
)

const q48 = 281474976710656.0 // 2^48

func fx(x chaossync.Fxp) float64 { return float64(x.Raw()) / q48 }

var (
	field = chaossync.DeriveField(chaossync.SelftestMaster, 424242)
	mu    [chaossync.Sites]float64
	eps1  float64
	eps2  float64
)

func main() {
	for i := 0; i < chaossync.Sites; i++ {
		mu[i] = fx(field.Mu[i])
	}
	eps1 = fx(field.Eps1)
	eps2 = fx(field.Eps2)
	fmt.Printf("# chaos-metrics на реальном ядре (мастер=SelftestMaster, эпоха=424242)\n")
	fmt.Printf("# поле эпохи: eps1=%.6f eps2=%.6f Drive=%d Next=%v\n#   mu per site: ",
		eps1, eps2, field.Drive, field.Next)
	for i := 0; i < chaossync.Sites; i++ {
		fmt.Printf("%.5f ", mu[i])
	}
	fmt.Println("\n")
	expA()
	expB()
	expC()
}

// ---------- Э-A: спектр Ляпунова и h_KS ----------

func expA() {
	fmt.Println("=== Э-A: спектр Ляпунова 8-сайтовой CML (Benettin, касательные float64 вдоль точной Q16.48-траектории) ===")
	const N = chaossync.Sites
	// связующая матрица M: x_i' = g_i + e1(g_prev - g_i) + e2(g_next - g_i)
	var M [N][N]float64
	for i := 0; i < N; i++ {
		M[i][i] = 1 - eps1 - eps2
		M[i][field.Prev[i]] = eps1
		M[i][field.Next[i]] = eps2
	}
	x := chaossync.EpochInit(chaossync.SelftestMaster, 424242)
	var V [N][N]float64
	for i := 0; i < N; i++ {
		V[i][i] = 1
	}
	transient, measure := 50000, 200000
	var sumLog [N]float64
	for step := 0; step < transient+measure; step++ {
		field.Step(&x) // ТОЧНАЯ Q16.48 траектория
		// Якобиан гладкой карты в текущей точке: J[i][j] = mu_j(1-2x_j)·M[i][j]
		var J [N][N]float64
		for j := 0; j < N; j++ {
			df := mu[j] * (1 - 2*fx(x[j]))
			for i := 0; i < N; i++ {
				J[i][j] = df * M[i][j]
			}
		}
		// протолкнуть касательные и ортонормировать (модиф. Грам-Шмидт)
		var NV [N][N]float64
		for i := 0; i < N; i++ {
			for j := 0; j < N; j++ {
				s := 0.0
				for k := 0; k < N; k++ {
					s += J[i][k] * V[k][j]
				}
				NV[i][j] = s
			}
		}
		V = NV
		var R [N]float64
		for j := 0; j < N; j++ {
			for i := 0; i < j; i++ {
				var dot, norm float64
				for k := 0; k < N; k++ {
					dot += V[k][j] * V[k][i]
					norm += V[k][i] * V[k][i]
				}
				for k := 0; k < N; k++ {
					V[k][j] -= dot / norm * V[k][i]
				}
			}
			var n float64
			for k := 0; k < N; k++ {
				n += V[k][j] * V[k][j]
			}
			n = math.Sqrt(n)
			R[j] = n
			for k := 0; k < N; k++ {
				V[k][j] /= n
			}
		}
		if step >= transient {
			for j := 0; j < N; j++ {
				sumLog[j] += math.Log(R[j])
			}
		}
	}
	var lam [N]float64
	hks := 0.0
	for j := 0; j < N; j++ {
		lam[j] = sumLog[j] / (float64(measure) * math.Ln2)
		if lam[j] > 0 {
			hks += lam[j]
		}
	}
	sort.Sort(sort.Reverse(sort.Float64Slice(lam[:])))
	fmt.Printf("показатели Ляпунова (бит/итерация): ")
	pos := 0
	for j := 0; j < N; j++ {
		fmt.Printf("%+.4f ", lam[j])
		if lam[j] > 0 {
			pos++
		}
	}
	fmt.Println()
	fmt.Printf("положительных экспонент: %d из %d\n", pos, N)
	fmt.Printf("h_KS = сумма положительных = %.4f бит/итерация (%.4f нат/итер)\n", hks, hks*math.Ln2)
	// Каплан-Йорк
	sum := 0.0
	dky := 0.0
	for j := 0; j < N; j++ {
		sum += lam[j]
		if sum < 0 {
			dky = float64(j) + (sum-lam[j])/math.Abs(lam[j])
			break
		}
	}
	fmt.Printf("размерность Каплана-Йорка D_KY ≈ %.3f\n", dky)

	// темп итераций на CPU ноды
	xb := chaossync.EpochInit(chaossync.SelftestMaster, 424242)
	t0 := time.Now()
	const NB = 5000000
	for i := 0; i < NB; i++ {
		field.Step(&xb)
	}
	dStep := time.Since(t0)
	// генераторная цепочка keystream-режима: Step + whiten (два SHA-256, как в KeyGen.next)
	var ctr [8]byte
	t0 = time.Now()
	var sink [32]byte
	for i := 0; i < NB; i++ {
		field.Step(&xb)
		var buf [8 + chaossync.Sites*8]byte
		binary.BigEndian.PutUint64(ctr[:], uint64(i))
		copy(buf[:8], ctr[:])
		for k := 0; k < chaossync.Sites; k++ {
			binary.BigEndian.PutUint64(buf[8+k*8:], uint64(xb[k].Raw()))
		}
		k1 := sha256.Sum256(buf[:])
		k2 := sha256.Sum256(k1[:])
		sink = k2
	}
	dGen := time.Since(t0)
	_ = sink
	ipsStep := float64(NB) / dStep.Seconds()
	ipsGen := float64(NB) / dGen.Seconds()
	fmt.Printf("темп на CPU ноды: чистая итерация %.2f млн итер/с (%.0f нс/шаг); итерация+whiten %.2f млн/с\n",
		ipsStep/1e6, dStep.Seconds()/NB*1e9, ipsGen/1e6)
	fmt.Printf("ПРОИЗВОДСТВО ЭНТРОПИИ локальной решёткой: %.2f Мбит/с при чистом темпе, %.2f Мбит/с с whiten\n",
		hks*ipsStep/1e6, hks*ipsGen/1e6)
	fmt.Println("(читается честно: это темп производства непредсказуемости ЛОКАЛЬНЫМ генератором — его уже")
	fmt.Println(" эксплуатирует keystream data-plane; ёмкость провода носителя-CSK это НЕ число, см. Э-B/Э-C)")
}

// ---------- Э-B: информация на сэмпл синхро-канала (M-арная модуляция) ----------

func expB() {
	fmt.Println("\n=== Э-B: бит/сэмпл синхро-многообразия — MI(уровень → residual) через реальный провод (Quantize16→ObserverStep) ===")
	c := chaossync.MustDecimal("0.85") // боевой дефолт протокола
	// шумовая полка: locked-остаток без модуляции
	sigma := idleSigma(c)
	fmt.Printf("locked-остаток без модуляции (шумовая полка): sigma_r = %.2e (сходимость из чужого состояния, 5к шагов транзиент)\n", sigma)
	fmt.Printf("шаг квантизации провода q = 2^-16 = %.2e\n", 1.0/65536)
	for _, dmax := range []float64{1.0 / 256, 1.0 / 64, 1.0 / 16} {
		fmt.Printf("-- бюджет возмущения deltaMax = 2^-%d:\n", int(math.Round(math.Log2(1/dmax))))
		for _, M := range []int{2, 4, 8, 16, 32, 64, 128} {
			mi := maryMI(M, dmax, c, 300000)
			fmt.Printf("   M=%3d: MI = %.3f бит/сэмпл (log2 M = %.1f; захват %.0f%%)\n",
				M, mi, math.Log2(float64(M)), 100*mi/math.Log2(float64(M)))
		}
	}
	fmt.Println("(базовая точка CSK: 1 бит / 32 сэмпла = 0.031 бит/сэмпл; при rate=1000 сэмпл/с = 31.25 бит/с)")
	fmt.Println("(оценка MI по гистограммам 512 корзин, N=300к на M; редкие корзины чуть завышают MI — смотреть на колено)")
}

// idleSigma — с.к.о. residual при полностью синхронном приёме без модуляции.
func idleSigma(c chaossync.Fxp) float64 {
	txF := chaossync.DeriveField(chaossync.SelftestMaster, 777)
	rxF := chaossync.DeriveField(chaossync.SelftestMaster, 777)
	tx := chaossync.EpochInit(chaossync.SelftestMaster, 777)
	rx := chaossync.EpochInit(chaossync.SelftestMaster, 778) // чужое начало
	for t := 0; t < 5000; t++ {
		txF.Step(&tx)
		rxF.ObserverStep(&rx, chaossync.Dequantize16(chaossync.Quantize16(tx[txF.Drive])), c)
	}
	const N = 100000
	var s, s2 float64
	for t := 0; t < N; t++ {
		txF.Step(&tx)
		y := chaossync.Quantize16(tx[txF.Drive])
		r := rxF.ObserverStep(&rx, chaossync.Dequantize16(y), c)
		v := fx(r)
		s += v
		s2 += v * v
	}
	mean := s / N
	return math.Sqrt(s2/N - mean*mean)
}

// maryMI — взаимная информация между случайным M-арным уровнем возмущения
// драйв-сайта и residual приёмника (бит/сэмпл), через реальный провод.
func maryMI(M int, dmax float64, c chaossync.Fxp, N int) float64 {
	txF := chaossync.DeriveField(chaossync.SelftestMaster, 777)
	rxF := chaossync.DeriveField(chaossync.SelftestMaster, 777)
	tx := chaossync.EpochInit(chaossync.SelftestMaster, 777)
	rx := chaossync.EpochInit(chaossync.SelftestMaster, 778)
	for t := 0; t < 5000; t++ {
		txF.Step(&tx)
		rxF.ObserverStep(&rx, chaossync.Dequantize16(chaossync.Quantize16(tx[txF.Drive])), c)
	}
	levels := make([]chaossync.Fxp, M)
	for k := 0; k < M; k++ {
		v := -dmax + 2*dmax*float64(k)/float64(M-1)
		levels[k] = chaossync.FromRaw(int64(v * q48))
	}
	rng := rand.New(rand.NewSource(int64(M * 131071)))
	// собираем residual'ы
	rs := make([]float64, 0, N)
	ls := make([]int, 0, N)
	for t := 0; t < N; t++ {
		txF.Step(&tx)
		li := rng.Intn(M)
		d := txF.Drive
		v := tx[d].Add(levels[li])
		if v < 0 {
			v = 0
		}
		if v >= chaossync.One {
			v = chaossync.One - 1
		}
		tx[d] = v
		y := chaossync.Quantize16(tx[d])
		r := rxF.ObserverStep(&rx, chaossync.Dequantize16(y), c)
		rs = append(rs, fx(r))
		ls = append(ls, li)
	}
	// гистограммы: адаптивный диапазон
	lo, hi := rs[0], rs[0]
	for _, v := range rs {
		if v < lo {
			lo = v
		}
		if v > hi {
			hi = v
		}
	}
	pad := (hi - lo) * 0.02
	lo -= pad
	hi += pad
	const B = 512
	counts := make([][]float64, M)
	for i := range counts {
		counts[i] = make([]float64, B)
	}
	colSum := make([]float64, B)
	for t := 0; t < N; t++ {
		b := int((rs[t] - lo) / (hi - lo) * B)
		if b < 0 {
			b = 0
		}
		if b >= B {
			b = B - 1
		}
		counts[ls[t]][b]++
		colSum[b]++
	}
	mi := 0.0
	pL := 1.0 / float64(M)
	for l := 0; l < M; l++ {
		rowSum := 0.0
		for b := 0; b < B; b++ {
			rowSum += counts[l][b]
		}
		if rowSum == 0 {
			continue
		}
		for b := 0; b < B; b++ {
			c := counts[l][b]
			if c == 0 {
				continue
			}
			prl := c / rowSum
			pr := colSum[b] / float64(N)
			mi += pL * prl * math.Log2(prl/pr)
		}
	}
	return mi
}

// ---------- Э-C: символьная энтропия + HGO PoC ----------

func expC() {
	fmt.Println("\n=== Э-C: генерирующее разбиение и HGO-контроль ===")
	// 1) энтропийная скорость символьного потока драйв-сайта (медианное разбиение)
	x := chaossync.EpochInit(chaossync.SelftestMaster, 424242)
	for t := 0; t < 50000; t++ {
		field.Step(&x)
	}
	const PRE = 200000
	vals := make([]float64, 0, PRE)
	for t := 0; t < PRE; t++ {
		field.Step(&x)
		vals = append(vals, fx(x[field.Drive]))
	}
	sort.Float64s(vals)
	median := vals[PRE/2]
	fmt.Printf("медиана драйв-сайта (разбиение): %.5f\n", median)
	const NS = 2000000
	const MAXN = 12
	counts := make([][]int, MAXN+1)
	for n := 1; n <= MAXN; n++ {
		counts[n] = make([]int, 1<<n)
	}
	var rolling [MAXN + 1]int
	total := 0
	for t := 0; t < NS; t++ {
		field.Step(&x)
		bit := 0
		if fx(x[field.Drive]) >= median {
			bit = 1
		}
		for n := 1; n <= MAXN; n++ {
			rolling[n] = ((rolling[n] << 1) | bit) & ((1 << n) - 1)
			if t >= n-1 {
				counts[n][rolling[n]]++
			}
		}
		total++
	}
	fmt.Printf("энтропия блоков символьного потока (медианное разбиение, N=%d):\n", total)
	fmt.Println("  n |   H_n бит | H_n/n | h_n=H_n-H_{n-1}")
	var prev float64
	var hcond float64
	for n := 1; n <= MAXN; n++ {
		var H float64
		var tot int
		for _, c := range counts[n] {
			tot += c
		}
		for _, c := range counts[n] {
			if c > 0 {
				p := float64(c) / float64(tot)
				H -= p * math.Log2(p)
			}
		}
		hcond = H - prev
		fmt.Printf(" %2d | %9.4f | %.4f | %.4f\n", n, H, H/float64(n), hcond)
		prev = H
	}
	fmt.Printf("энтропийная скорость потока (условная, n=12) ≈ %.4f бит/символ — верхняя граница читаемого с одного порога\n", hcond)

	// 2) HGO PoC: односайтовая логистика с фактическим mu драйв-сайта
	hgoPoC()
}

// hgoPoC — эпизодический HGO-контроль символьной последовательности
// (Hayes–Grebogi–Ott 1993) на одном логистическом сайте с mu поля эпохи.
// Эпизод: микро-возмущение p (|p| ≤ 2^-6) в начале, L свободных итераций,
// символ = знак(x-0.5) последней. Провод = Quantize16 состояния каждого шага.
func hgoPoC() {
	muL := mu[field.Drive]
	fmt.Printf("\nHGO PoC: логистика mu=%.5f (драйв-сайт поля), разбиение 0.5, приёмник = порог на проводе (без наблюдателя)\n", muL)
	f := func(x float64) float64 { return muL * x * (1 - x) }
	for _, L := range []int{6, 8, 10, 12, 14, 16} {
		const dmax = 1.0 / 64    // 2^-6
		const margin = 1.0 / 4096 // 2^-12 ≫ шаг квантизации 2^-16
		rng := rand.New(rand.NewSource(int64(1000 + L)))
		const N = 5000
		x := 0.4173
		for t := 0; t < 20000; t++ {
			x = f(x)
		}
		var succ, ber, fails int
		var sumAbs, maxAbs float64
		for b := 0; b < N; b++ {
			target := rng.Intn(2)
			best := math.NaN()
			const grid = 4096
			for k := 0; k <= grid; k++ {
				p := -dmax + 2*dmax*float64(k)/float64(grid)
				xs := x + p
				if xs < 0 || xs >= 1 {
					continue
				}
				for j := 0; j < L; j++ {
					xs = f(xs)
				}
				sym := 0
				if xs >= 0.5 {
					sym = 1
				}
				if sym == target && math.Abs(xs-0.5) >= margin {
					if math.IsNaN(best) || math.Abs(p) < math.Abs(best) {
						best = p
					}
				}
			}
			p := 0.0
			if math.IsNaN(best) {
				fails++
			} else {
				p = best
				succ++
				a := math.Abs(p)
				sumAbs += a
				if a > maxAbs {
					maxAbs = a
				}
			}
			// эпизод на проводе: возмущённое состояние + L свободных итераций
			x += p
			for j := 0; j < L; j++ {
				x = f(x)
			}
			yq := math.Floor(x*65536) / 65536 // провод: Quantize16
			sym := 0
			if yq >= 0.5 {
				sym = 1
			}
			if sym != target {
				ber++
			}
		}
		rate := float64(succ) / float64(N) / float64(L+1)
		fmt.Printf("L=%2d: управление %.2f%% (провалов %d), BER на проводе %.2e, |p| mean %.2e max %.2e, полезная скорость %.4f бит/сэмпл\n",
			L, 100*float64(succ)/N, fails, float64(ber)/N, sumAbs/float64(succ), maxAbs, rate)
	}
	// sanity: без контроля символы случайны относительно сообщения
	rng := rand.New(rand.NewSource(9))
	x := 0.4173
	for t := 0; t < 20000; t++ {
		x = f(x)
	}
	wrong := 0
	for b := 0; b < 5000; b++ {
		target := rng.Intn(2)
		x = f(x)
		sym := 0
		if x >= 0.5 {
			sym = 1
		}
		if sym != target {
			wrong++
		}
	}
	fmt.Printf("sanity (без контроля): BER = %.3f (ожидается ~0.5 — символы не коррелированы с сообщением)\n", float64(wrong)/5000)
	fmt.Println("(честная рамка: эпизод = L+1 сэмпла провода на бит; множитель к CSK(S=32) = 32/(L+1);")
	fmt.Println(" конвейерная подача бит каждый шаг требует совместного планирования будущих толчков — отдельный этап)")
}
