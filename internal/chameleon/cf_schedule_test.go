package chameleon

// cf_schedule_test.go — Этап F4: две стороны с одинаковой моделью выводят
// идентичные расписания, с разной — нет; эпохи защищают от replay.

import (
	"reflect"
	"sort"
	"testing"
	"time"
)

// Критерий этапа F: совпадение расписаний на обеих сторонах в 100% эпох.
func TestScheduleTwoSides100Percent(t *testing.T) {
	secret := DeriveSessionSecret([]byte("stage-f-seed"))
	model := []byte(`{"has_dpi":true,"dns_likely_hijack":true,"rst_ms":12}`)
	mh := ModelHash(model)
	const epochLen = 10 * time.Minute
	// Сторона A и сторона B независимо выводят расписания 50 эпох подряд.
	for epoch := uint64(1000); epoch < 1050; epoch++ {
		a := DeriveSchedule(secret, mh, epoch, epochLen)
		b := DeriveSchedule(secret, ModelHash(model), epoch, epochLen)
		if !reflect.DeepEqual(a.ChannelOrder, b.ChannelOrder) ||
			a.CARWindowOffset != b.CARWindowOffset ||
			!reflect.DeepEqual(a.BoardPollAt, b.BoardPollAt) ||
			!reflect.DeepEqual(a.SymbolPerm, b.SymbolPerm) {
			t.Fatalf("эпоха %d: стороны разошлись", epoch)
		}
	}
}

// Разная модель (другая сеть/другие правила) -> другое расписание. Другая
// эпоха -> другое расписание (ротация по времени).
func TestScheduleModelAndEpochSensitivity(t *testing.T) {
	secret := DeriveSessionSecret([]byte("stage-f-seed"))
	m1 := ModelHash([]byte(`{"has_dpi":true}`))
	m2 := ModelHash([]byte(`{"has_dpi":false}`))
	base := DeriveSchedule(secret, m1, 42, time.Hour)
	diffModel := DeriveSchedule(secret, m2, 42, time.Hour)
	diffEpoch := DeriveSchedule(secret, m1, 43, time.Hour)

	eq := func(a, b *Schedule) bool {
		return reflect.DeepEqual(a.ChannelOrder, b.ChannelOrder) &&
			a.CARWindowOffset == b.CARWindowOffset &&
			reflect.DeepEqual(a.BoardPollAt, b.BoardPollAt) &&
			reflect.DeepEqual(a.SymbolPerm, b.SymbolPerm)
	}
	if eq(base, diffModel) {
		t.Fatal("разные модели цензора дали то же расписание")
	}
	if eq(base, diffEpoch) {
		t.Fatal("соседние эпохи дали то же расписание")
	}
	// SymbolPerm обязан быть валидной перестановкой 0..63.
	perm := append([]int(nil), base.SymbolPerm...)
	sort.Ints(perm)
	for i, v := range perm {
		if v != i {
			t.Fatalf("SymbolPerm не перестановка: %v", perm)
		}
	}
	// Каналы — перестановка полного набора.
	ch := append([]string(nil), base.ChannelOrder...)
	sort.Strings(ch)
	if !reflect.DeepEqual(ch, []string{"board", "car", "ct", "dns"}) {
		t.Fatalf("ChannelOrder не перестановка каналов: %v", ch)
	}
	// Моменты опроса борда лежат внутри эпохи и отсортированы.
	for i, d := range base.BoardPollAt {
		if d < 0 || d >= time.Hour {
			t.Fatalf("BoardPollAt[%d]=%v вне эпохи", i, d)
		}
		if i > 0 && d < base.BoardPollAt[i-1] {
			t.Fatal("BoardPollAt не отсортирован")
		}
	}
}

// F3: привязка сообщений к эпохам — replay старой эпохи отбрасывается.
func TestEpochBindingAntiReplay(t *testing.T) {
	msg := []byte("next-entry=10.0.0.7:8443")
	bound := BindEpoch(msg, 100)

	got, epoch, err := CheckEpoch(bound, 100, 1)
	if err != nil || epoch != 100 || string(got) != string(msg) {
		t.Fatalf("текущая эпоха должна приниматься: %v", err)
	}
	// Предыдущая эпоха в окне допуска (переход через границу).
	if _, _, err := CheckEpoch(bound, 101, 1); err != nil {
		t.Fatalf("эпоха-1 в допуске должна приниматься: %v", err)
	}
	// Replay из глубокого прошлого — отбрасывается.
	if _, _, err := CheckEpoch(bound, 105, 1); err != ErrEpochOutOfWindow {
		t.Fatalf("replay должен отбрасываться, got %v", err)
	}
	// Сообщение из далёкого будущего — тоже.
	future := BindEpoch(msg, 200)
	if _, _, err := CheckEpoch(future, 100, 1); err != ErrEpochOutOfWindow {
		t.Fatalf("будущая эпоха вне допуска должна отбрасываться, got %v", err)
	}
	// Мусор без префикса.
	if _, _, err := CheckEpoch([]byte("short"), 100, 1); err != ErrEpochMalformed {
		t.Fatalf("битое сообщение: got %v", err)
	}
}

// EpochAt: границы эпох считаются правильно.
func TestEpochAt(t *testing.T) {
	t0 := time.Unix(3600, 0) // ровно час с нуля
	if e := EpochAt(t0, time.Hour); e != 1 {
		t.Fatalf("epoch=%d, want 1", e)
	}
	if e := EpochAt(t0.Add(-time.Second), time.Hour); e != 0 {
		t.Fatalf("epoch=%d, want 0", e)
	}
	// Расписание по моменту времени совпадает с расписанием его эпохи.
	secret := DeriveSessionSecret([]byte("stage-f-seed"))
	mh := ModelHash([]byte(`{}`))
	a := DeriveScheduleAt(secret, mh, t0.Add(123*time.Second), time.Hour)
	b := DeriveSchedule(secret, mh, 1, time.Hour)
	if a.Epoch != 1 || !reflect.DeepEqual(a.SymbolPerm, b.SymbolPerm) {
		t.Fatal("DeriveScheduleAt должен совпадать с DeriveSchedule той же эпохи")
	}
}
