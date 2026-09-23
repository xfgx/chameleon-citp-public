package chaossync

// cdt_cst_test.go — CST для CDT: явная идентичность туннеля поверх ротаций
// эпох. Проверяем: свой туннель работает, чужой master отбрасывается,
// фрагмент без CST (лабораторный) не проходит в CST-туннель, replay-окно
// straddle ведёт себя задокументированно, TunnelID стабилен и различителен.

import (
	"bytes"
	"testing"
	"time"
)

var (
	cstMasterA = bytes.Repeat([]byte{0x42}, 32)
	cstMasterB = bytes.Repeat([]byte{0x43}, 32)
	cstCfg     = GeomConfig{}.withDefaults()
	cstT       = uint64(8)
	cstBase    = time.Unix(1_700_000_000, 0)
)

// Свой туннель с CST работает; чужой master отбрасывается fail-closed.
func TestCDTCstWrongMasterRejected(t *testing.T) {
	frag := NewRotatingFragmenter(cstMasterA, cstCfg, cstT, cstBase)
	good := NewRotatingDefragmenter(cstMasterA, cstCfg, cstT, cstBase)
	bad := NewRotatingDefragmenter(cstMasterB, cstCfg, cstT, cstBase)

	frag.Push(bytes.Repeat([]byte{0xAB}, 5000))
	wire, _, ok := frag.Emit()
	if !ok {
		t.Fatal("emit failed")
	}
	if !good.Ingest(wire) {
		t.Fatal("свой фрагмент отброшен при CST")
	}
	if bad.Ingest(wire) {
		t.Fatal("чужой master прошёл при CST")
	}
}

// CST реально связывает фрагмент с цепочкой идентичности: фрагмент от
// лабораторного (без CST) фрагментера с тем же master и той же эпохой
// обязан быть отброшен ротационным дефрагментером — data-ключ и nonce
// совпадают, отличается только AAD.
func TestCDTCstBindsContinuity(t *testing.T) {
	ep := EpochFor(cstBase, cstT)
	lab := NewFragmenter(cstMasterA, ep, cstCfg) // burst: без CST
	tun := NewRotatingDefragmenter(cstMasterA, cstCfg, cstT, cstBase)

	lab.Push(bytes.Repeat([]byte{0xCD}, 3000))
	wire, _, ok := lab.Emit()
	if !ok {
		t.Fatal("emit failed")
	}
	if tun.Ingest(wire) {
		t.Fatal("фрагмент без CST прошёл в CST-туннель")
	}
}

// Replay: фрагмент эпохи m, не доставленный вовремя, принимается в окне
// straddle (m = prev при m+1 — задокументированная грейс-зона), повтор того
// же провода отбрасывается (nonce поглощён), а после выхода эпохи из окна
// фрагмент забывается окончательно.
func TestCDTCstCrossEpochReplay(t *testing.T) {
	frag := NewRotatingFragmenter(cstMasterA, cstCfg, cstT, cstBase)
	defrag := NewRotatingDefragmenter(cstMasterA, cstCfg, cstT, cstBase)

	frag.Push(bytes.Repeat([]byte{0xEF}, 4000))
	wire, _, ok := frag.Emit()
	if !ok {
		t.Fatal("emit failed")
	}
	// straddle: m+1 — запоздавший фрагмент эпохи m принимается (дизайн)
	t1 := cstBase.Add(time.Duration(cstT+1) * time.Second)
	frag.TickEpoch(t1)
	defrag.TickEpoch(t1)
	if !defrag.Ingest(wire) {
		t.Fatal("straggler границы эпохи отброшен в окне straddle")
	}
	// реальный replay (тот же провод дважды) — отброшен (nonce поглощён)
	if defrag.Ingest(wire) {
		t.Fatal("повторный фрагмент прошёл (replay внутри окна)")
	}
	// выход из окна: m+2 — эпоха m забыта
	t2 := cstBase.Add(time.Duration(2*cstT+1) * time.Second)
	defrag.TickEpoch(t2)
	if defrag.Ingest(wire) {
		t.Fatal("фрагмент забытой эпохи прошёл")
	}
}

// TunnelID: стабилен, одинаков у обеих сторон одного туннеля, различает
// master и направление, не зависит от эпохи.
func TestCDTTunnelID(t *testing.T) {
	a1 := TunnelID(cstMasterA, "c2n")
	if a1 != TunnelID(cstMasterA, "c2n") {
		t.Fatal("TunnelID нестабилен")
	}
	if a1 == TunnelID(cstMasterB, "c2n") {
		t.Fatal("TunnelID не различает master")
	}
	if a1 == TunnelID(cstMasterA, "n2c") {
		t.Fatal("TunnelID не различает направление")
	}
}
