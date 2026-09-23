package chameleon

// cf_car_test.go — Этап A4: тесты кодовой книги, FEC-кадра, пейсинга и
// loopback-интеграции CAR через MockCensor с шумом.

import (
	"math"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fastCARPacer — быстрый детерминированный пейсер для loopback-тестов
// (медиана 2 мс; боевой дефолт — 150 мс, задан в NewCARReader).
func fastCARPacer() *CARPacer { return newCARPacerSeeded(2*time.Millisecond, 0.6, 42) }

// --- A1: кодовая книга ---

// Две стороны с одним секретом обязаны вывести идентичную книгу, с разным —
// разную. Список меток при этом никогда не покидает стороны.
func TestCARCodebookTwoSidesSync(t *testing.T) {
	secret := DeriveSessionSecret([]byte("stage-a-seed"))
	a := NewCARCodebook(secret, 64)
	b := NewCARCodebook(secret, 64)
	for i := 0; i < 64; i++ {
		if a.Label(i) != b.Label(i) {
			t.Fatalf("окно %d: стороны с одним секретом разошлись (%s vs %s)", i, a.Label(i), b.Label(i))
		}
	}
	c := NewCARCodebook(DeriveSessionSecret([]byte("other-seed")), 64)
	diff := 0
	for i := 0; i < 64; i++ {
		if a.Label(i) != c.Label(i) {
			diff++
		}
	}
	if diff < 60 {
		t.Fatalf("разные секреты дали подозрительно похожие книги: различаются %d/64 окон", diff)
	}
}

// Метки не должны образовывать паттерн, который ловит наш verdict-probing
// детектор: никаких числовых/последовательных seq, все метки уникальны и не
// содержат триггерный токен (safe-by-default).
func TestCARCodebookEvadesSequentialPattern(t *testing.T) {
	book := NewCARCodebook(DeriveSessionSecret([]byte("stage-a-seed")), 128)
	seen := make(map[string]bool, book.Windows())
	for i := 0; i < book.Windows(); i++ {
		l := book.Label(i)
		if seen[l] {
			t.Fatalf("дубликат метки %q", l)
		}
		seen[l] = true
		if _, err := strconv.Atoi(l); err == nil {
			t.Fatalf("метка %q числовая — детектор словит sequential-паттерн", l)
		}
		if strings.Contains(l, CARForbiddenToken) {
			t.Fatalf("метка %q содержит триггерный токен", l)
		}
	}
}

// --- A2: кадрирование и FEC ---

func TestCARFrameRoundTrip(t *testing.T) {
	msgs := [][]byte{
		{0x5A},
		[]byte("next-entry=10.0.0.7:8443"),
		make([]byte, 255), // максимум
	}
	for _, rep := range []int{1, 3, 5} {
		for _, msg := range msgs {
			bits := EncodeCARFrame(msg, rep)
			if bits == nil {
				t.Fatalf("rep=%d len=%d: encode вернул nil", rep, len(msg))
			}
			if want := CARFrameWindows(len(msg), rep); len(bits) != want {
				t.Fatalf("rep=%d len=%d: %d бит, ожидалось %d окон", rep, len(msg), len(bits), want)
			}
			plen, err := DecodeCARFrameHeader(bits, rep)
			if err != nil || plen != len(msg) {
				t.Fatalf("rep=%d: header plen=%d err=%v, ожидалось %d", rep, plen, err, len(msg))
			}
			got, err := DecodeCARFrame(bits, rep)
			if err != nil {
				t.Fatalf("rep=%d len=%d: %v", rep, len(msg), err)
			}
			if len(got) != len(msg) || (len(msg) > 0 && string(got) != string(msg)) {
				t.Fatalf("rep=%d: roundtrip mismatch", rep)
			}
		}
	}
	// Переполнение — честный отказ.
	if EncodeCARFrame(make([]byte, CARMaxPayload+1), 3) != nil {
		t.Fatal("payload > CARMaxPayload должен отклоняться")
	}
}

// Одиночный флип в repetition-группе исправляется мажоритарно; двойной флип
// ловится CRC-16.
func TestCARFrameFECAndCRC(t *testing.T) {
	msg := []byte("k")
	const rep = 3

	bits := EncodeCARFrame(msg, rep)
	bits[20*rep] ^= 1 // одиночный флип в группе 20
	got, err := DecodeCARFrame(bits, rep)
	if err != nil || string(got) != string(msg) {
		t.Fatalf("одиночный флип должен исправляться: got=%q err=%v", got, err)
	}

	bits = EncodeCARFrame(msg, rep)
	bits[20*rep] ^= 1
	bits[20*rep+1] ^= 1 // двойной флип -> мажоритарная ошибка -> CRC
	if _, err := DecodeCARFrame(bits, rep); err == nil {
		t.Fatal("двойной флип в группе обязан ловиться CRC")
	}

	// Порча маркера начала.
	bits = EncodeCARFrame(msg, rep)
	bits[0] ^= 1
	bits[1] ^= 1
	if _, err := DecodeCARFrame(bits, rep); err == nil {
		t.Fatal("битый SYNC обязан отбрасывать кадр")
	}
}

// Критерий готовности этапа A (unit-уровень): сообщение восстанавливается
// при 10% инверсий бит. Детерминированный шум из DRBG — тест воспроизводим.
func TestCARFrameNoiseRecoveryUnit(t *testing.T) {
	msg := []byte{0x5A}
	flip := func(bits []uint8, seed byte, frac float64) []uint8 {
		noise := NewDRBG([]byte{seed}, "car-noise-test")
		for i := range bits {
			if float64(noise.Uint64()>>11)/float64(uint64(1)<<53) < frac {
				bits[i] ^= 1
			}
		}
		return bits
	}
	// rep=3 при 10% флипов: одиночная попытка проходит лишь иногда (~1/3),
	// поэтому боевой путь — CRC + перечитывание. Здесь проверяем семантику
	// retry: из 16 независимых шумовых выборок хотя бы одна обязана дойти.
	const draws = 16
	ok3 := 0
	for seed := byte(1); seed <= draws; seed++ {
		bits := flip(EncodeCARFrame(msg, CARFrameRep), seed, 0.10)
		if m, err := DecodeCARFrame(bits, CARFrameRep); err == nil && len(m) == 1 && m[0] == msg[0] {
			ok3++
		}
	}
	if ok3 == 0 {
		t.Fatal("rep=3: ни одна из 16 шумовых выборок не дошла — retry-стратегия бессильна")
	}
	// rep=5 при том же шуме: мажоритарная группа из 5 держит заметно лучше —
	// большинство попыток доходит без перечитывания.
	ok5 := 0
	for seed := byte(1); seed <= draws; seed++ {
		bits := flip(EncodeCARFrame(msg, 5), seed, 0.10)
		if m, err := DecodeCARFrame(bits, 5); err == nil && len(m) == 1 && m[0] == msg[0] {
			ok5++
		}
	}
	if ok5 < draws/2 {
		t.Fatalf("rep=5: только %d/%d выборок дошло при 10%% шуме", ok5, draws)
	}
	// Шумные попытки, не дошедшие целиком, обязаны отбраковываться CRC, а не
	// возвращать тихо повреждённое сообщение.
	bad := flip(EncodeCARFrame(msg, 1), 1, 0.10)
	if m, err := DecodeCARFrame(bad, 1); err == nil && len(m) == 1 && m[0] != msg[0] {
		t.Fatal("CRC пропустил тихо повреждённое сообщение")
	}
	t.Logf("10%% шум: rep=3 дошло %d/%d (нужны retry), rep=5 дошло %d/%d", ok3, draws, ok5, draws)
}

// --- A3: пейсинг против детектора query-cadence ---

// Детектор флагает CV < 0.15. Логнормальный пейсер (sigma 0.6) должен давать
// CV с большим запасом выше порога. Лог содержит готовую строку аргументов
// для прогона настоящего бинаря cham-detectors query-cadence.
func TestCARPacerEvadesCadenceDetector(t *testing.T) {
	p := newCARPacerSeeded(150*time.Millisecond, 0.6, 7)
	const n = 32
	d := make([]float64, n)
	for i := range d {
		d[i] = float64(p.Next()) / float64(time.Second)
	}
	mean := 0.0
	for _, x := range d {
		mean += x
	}
	mean /= n
	v := 0.0
	for _, x := range d {
		v += (x - mean) * (x - mean)
	}
	cv := math.Sqrt(v/n) / mean
	if cv < 0.20 {
		t.Fatalf("CV=%.3f слишком низок — query-cadence словит (порог 0.15)", cv)
	}
	// Метки времени для ручного прогона: go run ./tools/cham-detectors query-cadence <args>
	ts := make([]string, n)
	acc := 0.0
	for i, x := range d {
		acc += x
		ts[i] = strconv.FormatFloat(acc, 'f', 3, 64)
	}
	t.Logf("median=150ms sigma=0.6: CV=%.3f (порог детектора 0.15)", cv)
	t.Logf("cadence-args: %s", strings.Join(ts, " "))
}

// --- A4: loopback-интеграция ---

// Чистый канал: кадр с реальной командой доходит через кодовую книгу.
func TestCARLoopbackCodebookFrame(t *testing.T) {
	secret := DeriveSessionSecret([]byte("stage-a-loopback"))
	msg := []byte("next-entry=10.0.0.7:8443")
	book := NewCARCodebookForPayload(secret, len(msg), CARFrameRep)

	car := NewCARChannel("127.0.0.1:0")
	go func() { _ = car.Serve() }()
	carAddr := waitAddr(car.Addr)
	defer func() { _ = car.Shutdown() }()

	censor := NewMockCensor("127.0.0.1:0", "http://"+carAddr, "")
	go func() { _ = censor.Serve() }()
	censorAddr := waitAddr(censor.Addr)
	defer func() { _ = censor.Shutdown() }()

	if err := car.PublishFrame(book, msg, CARFrameRep); err != nil {
		t.Fatal(err)
	}
	reader := NewCARReader("http://" + censorAddr).WithPacer(fastCARPacer())
	got, err := reader.ReadMessage(book, CARFrameRep)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(msg) {
		t.Fatalf("loopback mismatch: got %q want %q", got, msg)
	}
}

// Критерий готовности этапа A: 8/8 бит сообщения восстанавливаются через
// MockCensor с 10% шумом. CRC ловит неисправимые кадры, читатель перечитывает
// (состояние на ноде статично -> каждая попытка — независимая шумовая выборка).
func TestCARLoopbackNoisy10Percent(t *testing.T) {
	secret := DeriveSessionSecret([]byte("stage-a-loopback"))
	book := NewCARCodebookForPayload(secret, 1, CARFrameRep)

	car := NewCARChannel("127.0.0.1:0")
	go func() { _ = car.Serve() }()
	carAddr := waitAddr(car.Addr)
	defer func() { _ = car.Shutdown() }()

	censor := NewMockCensor("127.0.0.1:0", "http://"+carAddr, "").
		WithNoise(0.10, []byte("stage-a-noise"))
	go func() { _ = censor.Serve() }()
	censorAddr := waitAddr(censor.Addr)
	defer func() { _ = censor.Shutdown() }()

	msg := []byte{0xA5}
	if err := car.PublishFrame(book, msg, CARFrameRep); err != nil {
		t.Fatal(err)
	}
	reader := NewCARReader("http://" + censorAddr).WithPacer(fastCARPacer())

	var got []byte
	var err error
	attempts := 0
	for ; attempts < 8; attempts++ {
		got, err = reader.ReadMessage(book, CARFrameRep)
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("кадр не восстановлен за %d попыток: %v", attempts+1, err)
	}
	if len(got) != 1 {
		t.Fatalf("ожидался 1 байт, получено %d", len(got))
	}
	diffBits := 0
	for i := 0; i < 8; i++ {
		if (got[0]>>i)&1 != (msg[0]>>i)&1 {
			diffBits++
		}
	}
	if diffBits != 0 {
		t.Fatalf("восстановлено %d/8 бит (10%% шум)", 8-diffBits)
	}
	t.Logf("8/8 бит восстановлены при 10%% шуме за %d попыток", attempts+1)
}
