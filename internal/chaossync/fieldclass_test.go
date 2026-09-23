package chaossync

// fieldclass_test.go — гейты задачи «классы полей / хаос-пол» (2026-09-01):
//
//   - санити целочисленного EstimateLambdaMax против эталонов Э-A
//     (ε=0 → λ₁≈0.835 бит/итер; прод-поле sync → λ₁≈±3e-6);
//   - все выданные FieldClassKeystream-поля проходят λ₁ ≥ KeystreamLambdaMin;
//   - sync-поля продолжают сходиться (регрессия carrier не сломана);
//   - детерминизм отбора/отбраковки: один мастер+эпоха → одна и та же
//     последовательность принятых/отбракованных (поле и число перерисовок
//     совпадают при повторном выводе);
//   - золотой вектор выбора полей обоих классов (бит-идентичность Win↔Linux;
//     значение зафиксировано прогоном на RU-ноде и сверено Windows-билдом
//     под wine — см. agent.md 2026-09-01).

import (
	"fmt"
	"testing"
	"time"
)

func fxpDbg(v Fxp) string { return fmt.Sprintf("%.6f", fxpToFloat(v)) }

// fcEpochs — эпохи гейтов (пересекаются с замерами Э-A).
var fcEpochs = []uint64{0, 1, 2, 3, 42, 77, 78, 1000, 424242, 999999}

// Эталоны Э-A (docs/CHAOS-METRICS.md): ε=0 (независимые сайты) → λ₁≈0.835
// бит/итер; прод-поле sync (эпоха 424242) → λ₁≈±3e-6. Целочисленный
// EstimateLambdaMax (телескопинг сдвигов) сверен с float-эталоном на той же
// орбите на ноде: 0.8380 против 0.8379 бит/итер — допуски ниже с запасом.
func TestLambdaSanityChaoticVsQuasiperiodic(t *testing.T) {
	base := DeriveField(SelftestMaster, 424242)
	// учебниковый хаос: независимые сайты (ε=0)
	chaotic := *base
	chaotic.Eps1 = FromRaw(0)
	chaotic.Eps2 = FromRaw(0)
	lc := EstimateLambdaMax(&chaotic, KeystreamLambdaIters)
	if lc < MustDecimal("0.7") || lc > MustDecimal("0.95") {
		t.Fatalf("хаос при ε=0: λ₁=%s бит/итер, ожидание [0.7, 0.95] (эталон Э-A 0.835)", fxpDbg(lc))
	}
	// прод-поле как есть: квазипериодика
	lq := EstimateLambdaMax(base, KeystreamLambdaIters)
	if lq.Abs() > MustDecimal("0.05") {
		t.Fatalf("прод-поле sync: λ₁=%s, ожидание |λ₁| ≤ 0.05 (эталон Э-A ±3e-6)", fxpDbg(lq))
	}
	t.Logf("sanity оценщика: хаос(ε=0) λ₁=%s бит/итер; прод-sync λ₁=%s", fxpDbg(lc), fxpDbg(lq))
}

func TestKeystreamFieldsPassChaosGate(t *testing.T) {
	for _, ep := range fcEpochs {
		p := DeriveFieldClass(SelftestMaster, ep, FieldClassKeystream)
		l := EstimateLambdaMax(p, KeystreamLambdaIters)
		t.Logf("эпоха %7d: λ₁=%s eps1=%.4f eps2=%.4f", ep, fxpDbg(l), fxpToFloat(p.Eps1), fxpToFloat(p.Eps2))
		if l < KeystreamLambdaMin {
			t.Fatalf("эпоха %d: выданное keystream-поле НЕ проходит свой же гейт: λ₁=%s < %s",
				ep, fxpDbg(l), fxpDbg(KeystreamLambdaMin))
		}
	}
}

func TestFieldSelectionDeterministic(t *testing.T) {
	for _, class := range []FieldClass{FieldClassSync, FieldClassKeystream} {
		p1, n1 := deriveFieldUncached(testMaster, 100, class)
		p2, n2 := deriveFieldUncached(testMaster, 100, class)
		if *p1 != *p2 || n1 != n2 {
			t.Fatalf("класс %d: вывод недетерминирован (перерисовок %d vs %d)", class, n1, n2)
		}
		p3, _ := deriveFieldUncached(testMaster, 101, class)
		if *p1 == *p3 {
			t.Fatalf("класс %d: соседние эпохи дали одинаковое поле", class)
		}
	}
}

// Отбраковка реально работает и детерминирована: порог выставляется выше
// измеренного λ₁ уже принятого поля → первый кандидат эпохи гарантированно
// отбраковывается (λ₁ вычисляется тем же бит-идентичным оценщиком), а
// следующий принят побитово воспроизводимо.
func TestChaosGateRejectsDeterministically(t *testing.T) {
	minEp := uint64(0)
	var minL Fxp
	var minP *FieldParams
	for ep := uint64(0); ep < 6; ep++ {
		p, _ := deriveFieldUncached(testMaster, ep, FieldClassKeystream)
		l := EstimateLambdaMax(p, KeystreamLambdaIters)
		if ep == 0 || l < minL {
			minEp, minL, minP = ep, l, p
		}
	}
	old := KeystreamLambdaMin
	defer func() { KeystreamLambdaMin = old }()
	// порог выше λ₁ принятого первого кандидата эпохи minEp
	KeystreamLambdaMin = minL.Add(MustDecimal("0.01"))
	p1, n1 := deriveFieldUncached(testMaster, minEp, FieldClassKeystream)
	if n1 < 2 {
		t.Fatalf("эпоха %d: отбраковки не произошло при пороге выше λ₁ первого кандидата", minEp)
	}
	l1 := EstimateLambdaMax(p1, KeystreamLambdaIters)
	if l1 < KeystreamLambdaMin {
		t.Fatalf("принятое после отбраковки поле не проходит порог: λ₁=%s < %s", fxpDbg(l1), fxpDbg(KeystreamLambdaMin))
	}
	if *p1 == *minP {
		t.Fatalf("эпоха %d: поле после отбраковки совпало с отбракованным кандидатом", minEp)
	}
	p2, n2 := deriveFieldUncached(testMaster, minEp, FieldClassKeystream)
	if *p1 != *p2 || n1 != n2 {
		t.Fatalf("эпоха %d: последовательность принятых/отбракованных недетерминирована", minEp)
	}
	t.Logf("отбраковка доказана: эпоха %d, порог %s, кандидатов %d, λ₁ принятого %s",
		minEp, fxpDbg(KeystreamLambdaMin), n1, fxpDbg(l1))
}

// Регрессия carrier: sync-поля продолжают проходить историческую пробу
// сходимости наблюдателя (критерий класса не менялся).
func TestSyncClassStillConverges(t *testing.T) {
	for _, ep := range []uint64{0, 1, 42, 424242} {
		p := DeriveFieldClass(SelftestMaster, ep, FieldClassSync)
		if !fieldConverges(SelftestMaster, ep, p) {
			t.Fatalf("sync-поле эпохи %d не проходит пробу сходимости", ep)
		}
	}
}

// fieldClassGoldenExpect — зафиксировано первым прогоном на RU-ноде (Linux
// amd64, Go 1.26.3) и сверено Windows-билдом под wine. Любой дрейф выбора
// полей (любого класса) или оценки λ₁ обязан упасть здесь.
const fieldClassGoldenExpect = "201644175985979813b959d9828835c2d2e5c9bc3ede41ed1a1e25b4d1b8d38d"

func TestFieldClassGolden(t *testing.T) {
	got := FieldClassGoldenVector()
	t.Logf("field-class golden: %s", got)
	if fieldClassGoldenExpect == "" {
		t.Skip("ожидание зафиксированного значения (первый прогон)")
	}
	if got != fieldClassGoldenExpect {
		t.Fatalf("выбор полей/λ₁ дрейфовал: got %s, want %s", got, fieldClassGoldenExpect)
	}
}

// Калибровочный лог (не гейт): приёмка и разброс λ₁ на потоке кандидатов
// keystream-класса + стоимость вывода поля. По этим числам финализируются
// KeystreamLambdaMin и бюджет ~50 мс/поле.
func TestLambdaCalibrationLog(t *testing.T) {
	var totAtt int
	var sumMs int64
	var minL, maxL Fxp
	for ep := uint64(0); ep < 12; ep++ {
		ts := time.Now()
		p, n := deriveFieldUncached(SelftestMaster, ep, FieldClassKeystream)
		el := time.Since(ts)
		l := EstimateLambdaMax(p, KeystreamLambdaIters)
		if ep == 0 || l < minL {
			minL = l
		}
		if ep == 0 || l > maxL {
			maxL = l
		}
		totAtt += n
		sumMs += el.Milliseconds()
		t.Logf("эпоха %2d: кандидатов=%d λ₁=%s eps1=%.4f eps2=%.4f derive=%d мс",
			ep, n, fxpDbg(l), fxpToFloat(p.Eps1), fxpToFloat(p.Eps2), el.Milliseconds())
	}
	t.Logf("ИТОГО: %d кандидатов на 12 эпох (приёмка %.0f%%), принятые λ₁ ∈ [%s, %s] при пороге %s; среднее время вывода поля %d мс",
		totAtt, 100.0*12.0/float64(totAtt), fxpDbg(minL), fxpDbg(maxL), fxpDbg(KeystreamLambdaMin), sumMs/12)
}
