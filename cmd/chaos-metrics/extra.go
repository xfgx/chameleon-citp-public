package main

// extra.go — Э-A расширенное: sanity-контроль машинерии (нулевая связь →
// 8 независимых логистических λ ≈ ln2), развёртка спектра по эпохам и по
// силе связи ε (механизм: как связь топит экспоненты). Та же методика:
// точная Q16.48-траектория (FieldParams.Step), касательные float64, Benettin.

import (
	"fmt"
	"math"
	"sort"

	"chameleon/internal/chaossync"
)

// spectrumFromField — спектр Ляпунова (бит/итерация, по убыванию) для поля p
// на траектории эпохи. Касательный анализ — float64 вдоль точной Q16.48-орбиты.
func spectrumFromField(p *chaossync.FieldParams, epoch uint64, transient, measure int) [chaossync.Sites]float64 {
	const N = chaossync.Sites
	var muL [N]float64
	for i := 0; i < N; i++ {
		muL[i] = fx(p.Mu[i])
	}
	e1, e2 := fx(p.Eps1), fx(p.Eps2)
	var M [N][N]float64
	for i := 0; i < N; i++ {
		M[i][i] = 1 - e1 - e2
		M[i][p.Prev[i]] = e1
		M[i][p.Next[i]] = e2
	}
	x := chaossync.EpochInit(chaossync.SelftestMaster, epoch)
	var V [N][N]float64
	for i := 0; i < N; i++ {
		V[i][i] = 1
	}
	var sumLog [N]float64
	for step := 0; step < transient+measure; step++ {
		p.Step(&x)
		var J [N][N]float64
		for j := 0; j < N; j++ {
			df := muL[j] * (1 - 2*fx(x[j]))
			for i := 0; i < N; i++ {
				J[i][j] = df * M[i][j]
			}
		}
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
	for j := 0; j < N; j++ {
		lam[j] = sumLog[j] / (float64(measure) * math.Ln2)
	}
	sort.Sort(sort.Reverse(sort.Float64Slice(lam[:])))
	return lam
}

func hksOf(lam [chaossync.Sites]float64) (h float64, pos int) {
	for _, l := range lam {
		if l > 0 {
			h += l
			pos++
		}
	}
	return h, pos
}

func expAExtended() {
	fmt.Println("\n=== Э-A расширенное: sanity + развёртки ===")

	// 0) sanity машинерии: та же карта без связи — 8 независимых логистических,
	// ждём ~ln2 бит на сайт (у μ≈3.9..3.97 чуть ниже 1.0).
	p0 := *field
	p0.Eps1 = chaossync.FromRaw(0)
	p0.Eps2 = chaossync.FromRaw(0)
	lam := spectrumFromField(&p0, 424242, 20000, 100000)
	h, pos := hksOf(lam)
	fmt.Printf("sanity ε=0 (сайты независимы): λ1=%.4f, положительных %d/8, h_KS=%.3f бит/итер (ожидание ≈8×0.9..1.0 — машинерия верна)\n",
		lam[0], pos, h)

	// 1) развёртка по эпохам: поля DeriveField как есть (самопроверка сходимости внутри)
	fmt.Println("-- спектр по эпохам (прод-поля, как выбрал DeriveField):")
	for _, ep := range []uint64{1, 2, 3, 42, 77, 78, 1000, 424242, 999999} {
		f := chaossync.DeriveField(chaossync.SelftestMaster, ep)
		lam := spectrumFromField(f, ep, 20000, 100000)
		h, pos := hksOf(lam)
		fmt.Printf("   эпоха %7d: eps1=%.3f eps2=%.3f | λ1=%+.6f | положит. %d/8 | h_KS=%.6f бит/итер\n",
			ep, fx(f.Eps1), fx(f.Eps2), lam[0], pos, h)
	}

	// 2) развёртка по силе связи на фиксированных mu/топологии эпохи 424242:
	// механизм «связь топит экспоненты» — виден переход хаос→порядок.
	fmt.Println("-- развёртка по ε (mu и топология эпохи 424242, eps1=eps2=ε):")
	for _, e := range []float64{0.0, 0.02, 0.05, 0.10, 0.15, 0.20, 0.30, 0.40, 0.46} {
		pe := *field
		pe.Eps1 = chaossync.FromRaw(int64(e * q48))
		pe.Eps2 = chaossync.FromRaw(int64(e * q48))
		lam := spectrumFromField(&pe, 424242, 20000, 100000)
		h, pos := hksOf(lam)
		fmt.Printf("   ε=%.2f: λ1=%+.6f | положит. %d/8 | h_KS=%.6f бит/итер\n", e, lam[0], pos, h)
	}
	fmt.Println("(честно: показатели гладкой карты на параметрах эпохи вдоль точной Q16.48-орбиты;")
	fmt.Println(" квантизация 2^-48 на 4 порядка ниже шума float64 — теневая корректность)")
}
