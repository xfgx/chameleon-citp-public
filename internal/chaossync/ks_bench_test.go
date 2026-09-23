package chaossync

// ks_bench_test.go — микробенчмарки горячего пути KS data-plane
// (2026-09-09, perf-разбор). Прогон:
//
//	go test ./internal/chaossync -run '^$' -bench 'Perf' -benchtime 1s -count 3
//
// Существующий BenchmarkKsSeal (ks_test.go, payload 1280B) не тронут —
// он задокументирован как метрика data-plane. Здесь — отдельные Perf-замеры
// с ReportAllocs для анализа аллокаций (драйвер perf-правок 2026-09-09).
// Golden-гейт бит-идентичности: TestKsGoldenVector (ks_test.go) — его
// прохождение после любой perf-правки обязательно.

import "testing"

// BenchmarkKsNextPerf — чистый keystream: шаг решётки + whiten + nonce
// на позицию (без AEAD и копирования провода).
func BenchmarkKsNextPerf(b *testing.B) {
	kg := NewKeyGen(SelftestMaster, 424242, "c2n")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		kg.next()
	}
}

// BenchmarkKsSealPerf — запечатывание одной датаграммы 1400B
// (сторона отправителя, MTU-размер).
func BenchmarkKsSealPerf(b *testing.B) {
	s := NewSender(SelftestMaster, 424242, "c2n")
	plain := make([]byte, 1400)
	b.ReportAllocs()
	b.SetBytes(1400)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.Seal(plain)
	}
}

// BenchmarkKsIngestPerf — приём валидной датаграммы 1400B (полный цикл
// приёмника: fill окна + поиск nonce + AEAD.Open). Провод готовится заранее
// пачками: nonce одноразовые, повторный Ingest того же провода честно
// отбрасывается, поэтому пачку перематываем вне таймера.
func BenchmarkKsIngestPerf(b *testing.B) {
	s := NewSender(SelftestMaster, 424242, "c2n")
	r := NewReceiver(SelftestMaster, 424242, "c2n")
	plain := make([]byte, 1400)
	const batch = 4096
	wires := make([][]byte, batch)
	for i := range wires {
		wires[i] = s.Seal(plain)
	}
	b.ReportAllocs()
	b.SetBytes(1400)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		j := i % batch
		if j == 0 && i > 0 {
			b.StopTimer()
			for k := range wires {
				wires[k] = s.Seal(plain)
			}
			b.StartTimer()
		}
		if _, ok := r.Ingest(wires[j]); !ok {
			b.Fatal("ingest failed")
		}
	}
}
