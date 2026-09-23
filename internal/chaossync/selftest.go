package chaossync

// selftest.go — канонический прогон ядра (этап Э1): фиксированный
// НЕ-секретный «мастер-ключ» (тестовый вектор), свободные траектории
// нескольких эпох, идеальная синхронизация с модуляцией и сходимость
// наблюдателя из чужого состояния. SHA-256 покрывает каждое состояние —
// побитовое сравнение Windows↔Linux сводится к сравнению одной строки.
//
// Воспроизводимость гарантируется конструкцией: ядро использует только
// целочисленную арифметику int64/uint64 (Go определяет переполнение
// однозначно на всех платформах), без float, без map-итераций, без
// зависимости от окружения.

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

// SelftestMaster — публичный тестовый вектор (не ключ!).
var SelftestMaster = []byte("chaossync-selftest-v1 NOT A SECRET")

// SelftestVector — хэш канонического прогона. Идентичен на любой платформе.
func SelftestVector() string {
	h := sha256.New()
	var buf [Sites * 8]byte
	writeState := func(x *[Sites]Fxp) {
		for i := 0; i < Sites; i++ {
			binary.BigEndian.PutUint64(buf[i*8:], uint64(x[i].Raw()))
		}
		h.Write(buf[:])
	}

	// Часть 1: свободные траектории эпох 0..4 (по 200 000 шагов каждая) —
	// покрывает DeriveField/EpochInit/Step для пяти разных полей.
	for e := uint64(0); e < 5; e++ {
		p := DeriveField(SelftestMaster, e)
		x := EpochInit(SelftestMaster, e)
		for s := 0; s < 200000; s++ {
			p.Step(&x)
			writeState(&x)
		}
	}

	cfg := Config{Master: SelftestMaster}.withDefaults()
	mod := Modulator{Delta: cfg.Delta, S: cfg.SymbolS}

	// Часть 2: идеальный канал tx→rx эпохи 77 с PN-модуляцией (50 000 шагов).
	tx := DeriveField(SelftestMaster, 77)
	rx := DeriveField(SelftestMaster, 77)
	txX := EpochInit(SelftestMaster, 77)
	rxX := EpochInit(SelftestMaster, 77)
	for s := uint64(0); s < 50000; s++ {
		tx.Step(&txX)
		bit := IdleBit(SelftestMaster, 77, s/uint64(cfg.SymbolS))
		mod.Perturb(&txX, tx.Drive, bit)
		y := Quantize16(txX[tx.Drive])
		r := rx.ObserverStep(&rxX, Dequantize16(y), cfg.Coupling)
		writeState(&rxX)
		var rb [8]byte
		binary.BigEndian.PutUint64(rb[:], uint64(r.Raw()))
		h.Write(rb[:])
	}

	// Часть 3: сходимость наблюдателя из «чужого» состояния (то же поле,
	// другое начало) — 5 000 шагов.
	rxX2 := EpochInit(SelftestMaster, 78)
	for s := 0; s < 5000; s++ {
		tx.Step(&txX)
		y := Quantize16(txX[tx.Drive])
		rx.ObserverStep(&rxX2, Dequantize16(y), cfg.Coupling)
		writeState(&rxX2)
	}

	return hex.EncodeToString(h.Sum(nil))
}

// FieldClassGoldenVector — хэш выбранных полей ОБОИХ классов (и оценок lambda1
// для keystream) на публичном мастере и фиксированных эпохах: гейт
// бит-идентичности ВЫБОРА ПОЛЯ Windows↔Linux (задача «хаос-пол», 2026-09-01).
// Оценка lambda1 целочисленная (lambda.go) → обязано совпасть на любой
// платформе; расхождение = стороны разойдутся в полях эпох, линк не встанет.
func FieldClassGoldenVector() string {
	h := sha256.New()
	var b [8]byte
	putRaw := func(v int64) { binary.BigEndian.PutUint64(b[:], uint64(v)); h.Write(b[:]) }
	putField := func(p *FieldParams) {
		for i := 0; i < Sites; i++ {
			putRaw(p.Mu[i].Raw())
		}
		putRaw(p.Eps1.Raw())
		putRaw(p.Eps2.Raw())
		for i := 0; i < Sites; i++ {
			putRaw(int64(p.Next[i]))
			putRaw(int64(p.Prev[i]))
		}
		putRaw(int64(p.Drive))
	}
	for _, class := range []FieldClass{FieldClassSync, FieldClassKeystream} {
		for _, e := range []uint64{0, 1, 2, 42, 77, 424242} {
			p := DeriveFieldClass(SelftestMaster, e, class)
			putField(p)
			if class == FieldClassKeystream {
				putRaw(EstimateLambdaMax(p, KeystreamLambdaIters).Raw())
			}
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}
