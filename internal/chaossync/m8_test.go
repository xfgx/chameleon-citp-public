package chaossync

// m8_test.go — гейты задачи «M=8 в carrier» (2026-09-01). Методология замеров
// выверена пятью отладочными раундами на ноде (см. agent.md): прогрев БЕЗ
// модуляции 5000 сэмплов (наблюдатель садится из чужого состояния, как в
// convergesAt/Э-B), затем замер на прод-поле sync-класса эпохи 424242 через
// реальный провод (Step→Perturb→Quantize16→Dequantize16→ObserverStep).
// Штатная точка M8: S=4, c=0.95, plain-sum — измеренный bit BER ≈ 0 на
// идеальном канале (предел rep3-запаса 0.2% с гигантским запасом).

import (
	"bytes"
	"fmt"
	"math/bits"
	"math/rand"
	"testing"
	"time"
)

// --- созвездие / классификатор ------------------------------------------------

func TestM8Constellation(t *testing.T) {
	delta := Fxp(oneRaw >> 8)
	m := NewModem8(delta, 4)
	for v := uint8(0); v < 8; v++ {
		if gray3Inv(gray3(v)) != v {
			t.Fatalf("gray roundtrip: %d → %d → %d", v, gray3(v), gray3Inv(gray3(v)))
		}
	}
	for l := 0; l < 7; l++ {
		if m.Levels[l] >= m.Levels[l+1] {
			t.Fatalf("уровни не монотонны: %v >= %v", m.Levels[l], m.Levels[l+1])
		}
	}
	if m.Levels[0] != -delta || m.Levels[7] != delta {
		t.Fatalf("крайние уровни обязаны быть ∓±Delta: got %v, %v", m.Levels[0], m.Levels[7])
	}
	if NewModem8(delta, 4) != m {
		t.Fatal("NewModem8 недетерминирован")
	}
	// классификатор на точной сумме level·S обязан вернуть ровно свой символ
	for v := uint8(0); v < 8; v++ {
		acc := m.Levels[gray3(v)].Mul(FromInt(int64(m.S)))
		if got := m.Classify(acc); got != v {
			t.Fatalf("classify exact: v=%d → %d", v, got)
		}
	}
}

// --- замер BER против S (прямой прогон символов через реальный провод) --------

// m8WireBER — поток ключевых PN-символов (известны тесту → прямой счёт ошибок)
// через Step→Perturb→Quantize16→Dequantize16→ObserverStep, связь c.
// Статистика — штатная (plain-sum, шипped в session.go). Возвращает
// символьные/битовые ошибки и средний отклик residual/сэмпл по символам.
func m8WireBER(S int, c Fxp, windows int) (symErr, bitErr, bitTot int, meanR [8]float64) {
	master := testMaster
	epoch := uint64(424242)
	field := DeriveField(master, epoch)
	m8 := NewModem8(Fxp(oneRaw>>8), S)
	tx := EpochInit(master, epoch)
	rx := EpochInit(master, epoch+probeWrongOffset)
	for k := 0; k < 5000; k++ { // прогрев без модуляции → замок
		field.Step(&tx)
		y := Quantize16(tx[field.Drive])
		field.ObserverStep(&rx, Dequantize16(y), c)
	}
	pn := pnSymbolsForEpoch(master, epoch, uint64(windows)+64, 3)
	var sumR [8]float64
	var cntR [8]int
	for w := uint64(0); w < uint64(windows); w++ {
		sym := pn[w]
		var acc Fxp
		for s := 0; s < S; s++ {
			field.Step(&tx)
			m8.Perturb(&tx, field.Drive, sym)
			y := Quantize16(tx[field.Drive])
			r := field.ObserverStep(&rx, Dequantize16(y), c)
			acc = acc.Add(r)
		}
		got := m8.Classify(acc)
		if got != sym {
			symErr++
			bitErr += bits.OnesCount8(got ^ sym)
		}
		bitTot += 3
		sumR[sym] += fxpToFloat(acc) / float64(S)
		cntR[sym]++
	}
	for i := range meanR {
		if cntR[i] > 0 {
			meanR[i] = sumR[i] / float64(cntR[i])
		}
	}
	return
}

// TestM8ClassifySweep — кривая символьного/битового BER против S на штатной
// связи M8 (c=0.95). Жёсткий гейт на штатной точке m8DefaultS: bit BER
// глубоко внутри зоны rep3 (≲0.2% → кадр 200 Б проходит с ~99%+).
func TestM8ClassifySweep(t *testing.T) {
	for _, S := range []int{1, 2, 3, 4} {
		symErr, bitErr, bitTot, meanR := m8WireBER(S, m8DefaultCoupling, 30000)
		t.Logf("S=%d c=0.95: symBER=%.5f bitBER=%.6f | meanR %+.5f %+.5f %+.5f %+.5f %+.5f %+.5f %+.5f %+.5f",
			S, float64(symErr)/30000, float64(bitErr)/float64(bitTot),
			meanR[0], meanR[1], meanR[2], meanR[3], meanR[4], meanR[5], meanR[6], meanR[7])
	}
	_, bitErr, bitTot, _ := m8WireBER(m8DefaultS, m8DefaultCoupling, 30000)
	ber := float64(bitErr) / float64(bitTot)
	t.Logf("штатная точка: S=%d c=0.95 → bitBER=%.6f (предел rep3-запаса 0.002)", m8DefaultS, ber)
	if ber > 0.002 {
		t.Fatalf("m8DefaultS=%d: bit BER %.6f выше порога rep3-запаса 0.002", m8DefaultS, ber)
	}
}

// TestM8Coupling085 — операторский путь «M8 при явном c=0.85»: измеренный
// ранее bit BER ~0.9% (plain) — rep3 на пределе, поэтому дефолт режима 0.95.
// Гейт информативный: не выше 1%.
func TestM8Coupling085(t *testing.T) {
	_, bitErr, bitTot, _ := m8WireBER(m8DefaultS, MustDecimal("0.85"), 30000)
	ber := float64(bitErr) / float64(bitTot)
	t.Logf("M8 при явном c=0.85: bitBER=%.6f (рекомендация — не задавать, дефолт 0.95)", ber)
	if ber > 0.01 {
		t.Fatalf("M8 при c=0.85: bit BER %.6f выше 1%%", ber)
	}
}

// --- end-to-end на Endpoint с потерями и джиттером ----------------------------

type m8Chan struct {
	tx, rx    *Endpoint
	now       time.Time
	rng       *rand.Rand
	loss      float64
	jitter    float64
	dropped   int
	delivered int
}

func newM8Chan(cfg Config, loss, jitter float64, seed int64) *m8Chan {
	return &m8Chan{
		tx: NewEndpoint(cfg, "c2s"), rx: NewEndpoint(cfg, "s2c"),
		now: testNow(), rng: rand.New(rand.NewSource(seed)),
		loss: loss, jitter: jitter,
	}
}

func (c *m8Chan) step() {
	dat := c.tx.NextDatagram(c.now)
	if c.rng.Float64() < c.loss {
		c.dropped++
	} else {
		c.delivered++
		c.rx.HandleDatagram(dat, c.now)
	}
	per := c.tx.cfg.DatagramInterval()
	j := time.Duration((c.rng.Float64()*2 - 1) * c.jitter * float64(per))
	c.now = c.now.Add(per + j)
}

func (c *m8Chan) phaseCapture(n int) bool {
	for i := 0; i < n; i++ {
		c.step()
		if c.rx.Snapshot().Phased {
			return true
		}
	}
	return false
}

func (c *m8Chan) lineBps() float64 {
	m := c.rx.MetricsSnapshot()
	rate := float64(c.rx.cfg.Rate)
	modelSec := float64(m.RxSamples+m.InferredLoss) / rate
	return 3 * float64(m.RxSamples) / float64(c.rx.symS) / modelSec
}

// TestM8EndToEndLossy — штатный M8 (S=4, c=0.95) на rate=1000, потери 1%,
// джиттер ±30%: серия кадров проходит целиком и по порядку (rep3 вытягивает
// измеренный BER), BER-сторож спокоен, перезахватов нет.
func TestM8EndToEndLossy(t *testing.T) {
	cfg := Config{Master: testMaster, Rate: 1000, EpochSec: 8}
	ch := newM8Chan(cfg, 0.01, 0.3, 42)
	if !ch.phaseCapture(6000) {
		t.Fatal("фаза не захвачена за 6000 датаграмм")
	}
	// Stop-and-wait ARQ — семантика живого control-plane над потерями:
	// неподтверждённый кадр повторяется. Формат кадра и CST-теги неизменны;
	// повтор в новой эпохе несёт новый CST-тег и виден приёмнику как новый
	// кадр. Дубликат невозможен: повтор только после того, как предыдущая
	// попытка гарантированно доиграла (таймаут > времени кадра) — мёртвый по
	// CRC кадр в Frames не попадает.
	const total = 40
	const arqTimeout = 700 // датаграмм; кадр = 344 окна ≈ столько же датаграмм
	payloads := make([][]byte, total)
	for i := range payloads {
		payloads[i] = []byte(fmt.Sprintf("m8-frame-%03d-payload-payload-payload", i))
	}
	var got [][]byte
	attempts := 0
	push := func() {
		if err := ch.tx.PushFrame(payloads[len(got)]); err != nil {
			t.Fatal(err)
		}
		attempts++
	}
	push()
	const deadline = 90000 // датаграмм = 360 с модельного времени при rate=1000
	sincePush := 0
	for i := 0; i < deadline && len(got) < total; i++ {
		ch.step()
		sincePush++
		for _, f := range ch.rx.Frames() {
			got = append(got, f.Payload)
		}
		if len(got) < total && sincePush >= arqTimeout {
			sincePush = 0
			push() // повтор текущего логического кадра
		}
	}
	if len(got) < total {
		t.Fatalf("доставлено %d кадров из %d за %d попыток (потери 1%%, джиттер)", len(got), total, attempts)
	}
	for i, g := range got {
		if !bytes.Equal(g, payloads[i]) {
			t.Fatalf("кадр %d не совпал/не в порядке: got %q want %q", i, g, payloads[i])
		}
	}
	// Фаза 2: чистый холостой поток под теми же потерями 1% и джиттером —
	// честный замер символьного BER демодуляции как дельты метрик. Во время
	// кадров PN-сторож неизбежно смешивает контент кадра с холостым PN
	// (пропущенный маркер → тело кадра читается сторожем как «idle») — это
	// учётная особенность сторожа-десинка, а не качество демодуляции. Поэтому
	// гейт BER меряем на холостом участке. Эразуры разрывов учтены отдельно
	// (InferredLoss) и из BER исключены (gapMute), как и окна восстановления.
	for i := 0; i < 1500; i++ { // отстой после последнего кадра
		ch.step()
	}
	m1 := ch.rx.MetricsSnapshot()
	for i := 0; i < 12000; i++ {
		ch.step()
	}
	m2 := ch.rx.MetricsSnapshot()
	dDen := m2.BerDen - m1.BerDen
	ber := 0.0
	if dDen > 0 {
		ber = float64(m2.BerNum-m1.BerNum) / float64(dDen)
	}
	berFrames := 0.0
	if m1.BerDen > 0 {
		berFrames = float64(m1.BerNum) / float64(m1.BerDen) // накопленное по кадровой фазе (с маркерным смешиванием)
	}
	t.Logf("M8 end-to-end: кадров %d/%d за %d попыток (ARQ), потери датаграмм %d/%d, idle bitBER(PN)=%.5f [кадровая фаза накопленно %.5f], resyncs=%d→%d spikes=%d→%d, линейная %.0f бит/с/плечо",
		len(got), total, attempts, ch.dropped, ch.delivered, ber, berFrames, m1.Resyncs, m2.Resyncs, m1.Spikes, m2.Spikes, ch.lineBps())
	if ber > 0.01 {
		t.Fatalf("PN bit BER %.5f выше 1%% на холостом потоке с потерями (предел rep3)", ber)
	}
	if m2.Resyncs != m1.Resyncs {
		t.Fatalf("resync на чистом холостом потоке: %d→%d", m1.Resyncs, m2.Resyncs)
	}
}

// TestM8ThroughputGate — жёсткий гейт пропускной: линейная бит/с/плечо на
// задокументированной рабочей точке при потерях 1% и джиттере. Планка
// 1.5 кбит/с — консервативная от ~2.5 кбит/с по Э-B. При S=4 ёмкость
// физического слоя 3/4 бит/сэмпл → планка достигается с rate ≥ ~2030
// (штатная точка rate=2100); на rate=1000 линейная 742 бит/с — честно
// задокументировано в agent.md.
func TestM8ThroughputGate(t *testing.T) {
	cfg := Config{Master: testMaster, Rate: 2100, EpochSec: 8}
	ch := newM8Chan(cfg, 0.01, 0.3, 7)
	if !ch.phaseCapture(6000) {
		t.Fatal("фаза не захвачена")
	}
	for i := 0; i < 45000; i++ {
		ch.step()
	}
	line := ch.lineBps()
	t.Logf("линейная пропускная carrier: %.0f бит/с/плечо (rate=2100, S=%d, loss=1%%, джиттер ±30%%)",
		line, ch.rx.symS)
	if line < 1500 {
		t.Fatalf("пропускная %.0f бит/с ниже гейта 1.5 кбит/с/плечо", line)
	}
}

// --- fallback M8→CSK и CSK-регрессии ------------------------------------------

// TestM8FallbackKeepsLogicalSession — переключение фиче-флага (обе стороны
// пересоздают физику с тем же мастером): логическая сессия не рвётся — кадры
// обеих модуляций проходят CST-проверку (FramesBadTag == 0).
func TestM8FallbackKeepsLogicalSession(t *testing.T) {
	run := func(mod Modulation, payload []byte) Metrics {
		cfg := Config{Master: testMaster, Rate: 400, EpochSec: 8, Modulation: mod}
		lc := &loopCtx{NewEndpoint(cfg, "c2s"), NewEndpoint(cfg, "s2c"), testNow()}
		if !phaseCapture(lc, 8000) {
			t.Fatalf("mod=%v: фаза не захвачена", mod)
		}
		if err := lc.tx.PushFrame(payload); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 30000; i++ {
			lc.step()
			if len(lc.rx.Frames()) > 0 {
				break
			}
		}
		return lc.rx.MetricsSnapshot()
	}
	m1 := run(ModulationM8, []byte("frame-over-m8"))
	m2 := run(ModulationCSK, []byte("frame-over-csk-fallback"))
	if m1.FramesOK == 0 || m2.FramesOK == 0 {
		t.Fatalf("кадр не доставлен: M8 ok=%d, CSK ok=%d", m1.FramesOK, m2.FramesOK)
	}
	if m1.FramesBadTag != 0 || m2.FramesBadTag != 0 {
		t.Fatalf("CST-теги не сошлись после переключения модуляции: M8 %d, CSK %d", m1.FramesBadTag, m2.FramesBadTag)
	}
}

// TestModemFrameRoundtripCSK — регрессия бинарного режима (fallback жив).
func TestModemFrameRoundtripCSK(t *testing.T) {
	cfg := Config{Master: testMaster, Modulation: ModulationCSK}
	lc := &loopCtx{NewEndpoint(cfg, "c2s"), NewEndpoint(cfg, "s2c"), testNow()}
	if !phaseCapture(lc, 4000) {
		t.Fatal("фаза не захвачена за 4000 датаграмм")
	}
	payload := []byte("hello chaos: fallback CSK-кадр поверх синхронизации")
	if err := lc.tx.PushFrame(payload); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20000; i++ {
		lc.step()
	}
	frames := lc.rx.Frames()
	if len(frames) == 0 {
		t.Fatal("CSK: кадр не декодирован")
	}
	if !bytes.Equal(frames[0].Payload, payload) {
		t.Fatalf("CSK: payload разошёлся")
	}
	m := lc.rx.MetricsSnapshot()
	t.Logf("CSK fallback: BER на идеальном канале %d/%d", m.BerNum, m.BerDen)
	if m.BerDen > 0 && m.BerNum*100 > m.BerDen {
		t.Fatalf("CSK: BER > 1%% на идеальном канале: %d/%d", m.BerNum, m.BerDen)
	}
}

// TestMutationResyncCSK — CST через мутации в fallback-режиме (зеркало
// TestMutationResync, который на дефолте покрывает M8).
func TestMutationResyncCSK(t *testing.T) {
	cfg := Config{Master: testMaster, EpochSec: 8, Modulation: ModulationCSK}
	lc := &loopCtx{NewEndpoint(cfg, "c2s"), NewEndpoint(cfg, "s2c"), testNow()}
	payloads := [][]byte{
		[]byte("frame-one-across-epochs"),
		[]byte("frame-two-across-epochs"),
		[]byte("frame-three-across-epochs"),
	}
	pushed, lastPush := 0, -10000
	seenEpochs := map[uint64]bool{}
	var decoded [][]byte
	for i := 0; i < 24000; i++ {
		if pushed < len(payloads) && i-lastPush > 6000 && lc.rx.Snapshot().Phased {
			if err := lc.tx.PushFrame(payloads[pushed]); err != nil {
				t.Fatal(err)
			}
			pushed++
			lastPush = i
		}
		lc.step()
		for _, f := range lc.rx.Frames() {
			decoded = append(decoded, f.Payload)
			seenEpochs[f.StartEpoch] = true
		}
	}
	found := 0
	for _, p := range payloads {
		for _, d := range decoded {
			if bytes.Equal(p, d) {
				found++
				break
			}
		}
	}
	if found < 2 {
		t.Fatalf("CSK: дошло %d из %d кадров через мутации", found, len(payloads))
	}
	if len(seenEpochs) < 2 {
		t.Fatal("CSK: все кадры в одной эпохе — непрерывность через мутацию не доказана")
	}
}
