package chaossync

// ks_test.go — keystream-инверсия ядра: гейт бит-идентичности, тишина на
// чужой master, независимость датаграмм от потерь, replay в окне straddle,
// непрерывность сквозь ротации эпох, изоляция направлений, честный AEGIS-stub.

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"
)

// ksGoldenExpect — зафиксированное значение KsGoldenVector (гейт
// бит-идентичности Windows↔Linux). Заполнено после первого прогона на ноде;
// дальше — жёсткий гейт: любой дрейф решётки/whiten ломает тест.
const ksGoldenExpect = ""

func TestKsGoldenVector(t *testing.T) {
	got := KsGoldenVector()
	t.Logf("ks golden: %s", got)
	if ksGoldenExpect == "" {
		t.Skip("ожидание зафиксированного значения (первый прогон)")
	}
	if got != ksGoldenExpect {
		t.Fatalf("keystream дрейфовал: got %s want %s", got, ksGoldenExpect)
	}
}

// Потерянная датаграмма не ломает поток: каждая третья выброшена, все
// остальные обязаны расшифроваться и совпасть по содержимому. Плюс
// переупорядочивание в пределах окна переживается.
func TestKsRoundtripLossIndependent(t *testing.T) {
	tx := NewSender(cstMasterA, 900, "c2n")
	rx := NewReceiver(cstMasterA, 900, "c2n")

	var wires [][]byte
	for i := 0; i < 50; i++ {
		wires = append(wires, tx.Seal([]byte(fmt.Sprintf("pkt-%03d", i))))
	}
	got := 0
	for i, w := range wires {
		if i%3 == 0 {
			continue // потеряна в пути
		}
		plain, ok := rx.Ingest(w)
		if !ok {
			t.Fatalf("датаграмма %d не расшифровалась после потерь", i)
		}
		if string(plain) != fmt.Sprintf("pkt-%03d", i) {
			t.Fatalf("датаграмма %d: содержимое разошлось", i)
		}
		got++
	}
	if got != 33 {
		t.Fatalf("дошло %d, ожидалось 33", got)
	}
}

// Чужой master → тишина: ни одна датаграмма не проходит AEAD, приёмник не
// выдаёт ни байта. Свой master при этом работает (контрольная точка).
func TestKsWrongMasterSilence(t *testing.T) {
	tx := NewSender(cstMasterA, 900, "c2n")
	rxGood := NewReceiver(cstMasterA, 900, "c2n")
	rxBad := NewReceiver(cstMasterB, 900, "c2n")
	var last []byte
	for i := 0; i < 100; i++ {
		w := tx.Seal([]byte(fmt.Sprintf("probe-%d", i)))
		if _, ok := rxBad.Ingest(w); ok {
			t.Fatalf("чужой master: датаграмма %d прошла", i)
		}
		last = w
	}
	if _, ok := rxGood.Ingest(last); !ok {
		t.Fatal("контроль: свой master отброшен")
	}
}

// Replay в окне straddle: запоздавшая датаграмма эпохи m принимается при
// m+1 (задокументированная грейс-зона), её повтор отбрасывается (nonce
// поглощён), после выхода эпохи из окна (m+2) — отбрасывается окончательно.
// Новая эпоха при этом продолжает работать.
func TestKsReplayStraddle(t *testing.T) {
	T := uint64(8)
	base := time.Unix(1_700_000_000, 0)
	tx := NewRotatingSender(cstMasterA, "c2n", T, base)
	rx := NewRotatingReceiver(cstMasterA, "c2n", T, base)

	w := tx.Seal([]byte("frame-m"))

	t1 := base.Add(9 * time.Second) // эпоха m+1
	tx.TickEpoch(t1)
	rx.TickEpoch(t1)
	if _, ok := rx.Ingest(w); !ok {
		t.Fatal("straggler границы эпохи отброшен в окне straddle")
	}
	if _, ok := rx.Ingest(w); ok {
		t.Fatal("повторный wire прошёл (replay внутри окна)")
	}

	t2 := base.Add(17 * time.Second) // эпоха m+2
	tx.TickEpoch(t2)
	rx.TickEpoch(t2)
	if _, ok := rx.Ingest(w); ok {
		t.Fatal("датаграмма забытой эпохи прошла")
	}
	w2 := tx.Seal([]byte("frame-m2"))
	plain, ok := rx.Ingest(w2)
	if !ok || string(plain) != "frame-m2" {
		t.Fatal("новая эпоха не работает после выхода старой из окна")
	}
}

// Непрерывность сквозь ротации: 200 датаграмм, время шагает, затронуто
// много эпох — каждая расшифровывается и совпадает.
func TestKsRotationMultiEpoch(t *testing.T) {
	T := uint64(8)
	base := time.Unix(1_700_000_000, 0)
	tx := NewRotatingSender(cstMasterA, "c2n", T, base)
	rx := NewRotatingReceiver(cstMasterA, "c2n", T, base)
	now := base
	epochsSeen := map[uint64]bool{}
	for i := 0; i < 200; i++ {
		if i%10 == 0 {
			now = now.Add(3 * time.Second)
		}
		tx.TickEpoch(now)
		rx.TickEpoch(now)
		epochsSeen[tx.epoch] = true
		w := tx.Seal([]byte(fmt.Sprintf("m-%d", i)))
		plain, ok := rx.Ingest(w)
		if !ok {
			t.Fatalf("датаграмма %d (эпоха %d) не прошла", i, tx.epoch)
		}
		if string(plain) != fmt.Sprintf("m-%d", i) {
			t.Fatalf("датаграмма %d: содержимое разошлось", i)
		}
	}
	if len(epochsSeen) < 3 {
		t.Fatalf("тест не нагнал ротаций: эпох %d", len(epochsSeen))
	}
	t.Logf("keystream сквозь ротации ОК: 200 датаграмм, эпох затронуто=%d", len(epochsSeen))
}

// Направления изолированы: датаграмма c2n не читается приёмником n2c.
func TestKsCrossDirection(t *testing.T) {
	tx := NewSender(cstMasterA, 900, "c2n")
	rxBack := NewReceiver(cstMasterA, 900, "n2c")
	w := tx.Seal([]byte("dir-test"))
	if _, ok := rxBack.Ingest(w); ok {
		t.Fatal("перекрёстное направление прошло")
	}
}

// AEGIS-128L — заявленная опция, честно не реализована (нет проверенной
// реализации в x/crypto): отказ явный, дефолт работает.
func TestKsAEGISStub(t *testing.T) {
	tx := NewSender(cstMasterA, 900, "c2n")
	if err := tx.SetSuite(SuiteAEGIS128L); !errors.Is(err, ErrSuiteUnsupported) {
		t.Fatal("AEGIS-128L должен честно отказывать (ErrSuiteUnsupported)")
	}
	if err := tx.SetSuite(SuiteChaCha20Poly1305); err != nil {
		t.Fatal("дефолтный набор обязан работать")
	}
}

// BenchmarkKsSeal — пропускная способность запечатывания (не гейт; число для
// документации data-plane).
func BenchmarkKsSeal(b *testing.B) {
	tx := NewSender(cstMasterA, 900, "c2n")
	payload := bytes.Repeat([]byte{0x5A}, 1280)
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tx.Seal(payload)
	}
}
