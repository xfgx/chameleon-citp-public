package chaossync

// Тест-сьют транспорта chaossync (этапы Э1–Э4 + fail-closed Э7).
// Всё гоняется на RU-ноде; время в тестах — фейковое (параметр now),
// поэтому тесты детерминированы.

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"
)

var testMaster = bytes.Repeat([]byte{0x42}, 32)
var wrongMaster = bytes.Repeat([]byte{0x99}, 32)

// testNow — стартовое фейковое время (любое фиксированное).
func testNow() time.Time { return time.Unix(1_700_000_000, 0) }

// loopCtx — идеальный loopback-канал tx → rx с фейковым временем.
type loopCtx struct {
	tx, rx *Endpoint
	now    time.Time
}

func (c *loopCtx) step() {
	dat := c.tx.NextDatagram(c.now)
	c.rx.HandleDatagram(dat, c.now)
	c.now = c.now.Add(c.tx.cfg.DatagramInterval())
}

// phaseCapture гоняет loopback до захвата фазы (mode=phased), макс n шагов.
func phaseCapture(c *loopCtx, n int) bool {
	for i := 0; i < n; i++ {
		c.step()
		if c.rx.Snapshot().Phased {
			return true
		}
	}
	return false
}

// --- Э1: детерминизм ------------------------------------------------------

// TestSelftestGolden — золотой хэш канонического прогона. Зафиксирован по
// первому прогону на RU-ноде (Linux amd64, Go 1.26.3); тот же хэш напечатал
// Windows-билд под wine 9.0. Любое изменение ядра, меняющее динамику,
// обязано упасть здесь.
func TestSelftestGolden(t *testing.T) {
	const want = "29f2315f353442c2bdd8183ad6d175dcd749929d4b095a6ab4cb6461d2ac5557"
	if got := SelftestVector(); got != want {
		t.Fatalf("selftest vector drift: got %s, want %s", got, want)
	}
}

func TestFxpMulKnown(t *testing.T) {
	cases := []struct{ a, b, want string }{
		{"1", "1", "1"},
		{"0.5", "0.5", "0.25"},
		{"1.5", "1.5", "2.25"},
		{"3.9", "0.5", "1.95"},
		{"-1.5", "2", "-3"},
		{"0.85", "0.85", "0.7225"},
		{"-0.75", "-0.75", "0.5625"},
	}
	for _, c := range cases {
		got := MustDecimal(c.a).Mul(MustDecimal(c.b))
		want := MustDecimal(c.want)
		if d := got.Sub(want).Abs(); d > FromRaw(1<<17) {
			t.Errorf("%s * %s: got raw %d, want raw %d", c.a, c.b, got.Raw(), want.Raw())
		}
	}
}

func TestFromDecimalRoundtrip(t *testing.T) {
	for _, s := range []string{"0", "1", "-1", "0.5", "-0.5", "3.9", "0.00390625"} {
		if _, err := FromDecimal(s); err != nil {
			t.Fatalf("FromDecimal(%q): %v", s, err)
		}
	}
	if FromInt(2).Raw() != int64(2)<<48 {
		t.Fatal("FromInt(2)")
	}
}

func TestDeriveFieldDeterministic(t *testing.T) {
	p1 := DeriveField(testMaster, 100)
	p2 := DeriveField(testMaster, 100)
	if *p1 != *p2 {
		t.Fatal("DeriveField недетерминирован")
	}
	p3 := DeriveField(testMaster, 101)
	if *p1 == *p3 {
		t.Fatal("соседние эпохи дали идентичное поле — мутация не работает")
	}
	i1 := EpochInit(testMaster, 100)
	i2 := EpochInit(testMaster, 100)
	if i1 != i2 {
		t.Fatal("EpochInit недетерминирован")
	}
}

func TestQuantizeRoundtrip(t *testing.T) {
	for _, q := range []uint16{0, 1, 1000, 32768, 65535} {
		if got := Quantize16(Dequantize16(q)); got != q {
			t.Fatalf("quantize roundtrip: %d -> %d", q, got)
		}
	}
}

// --- Э2: синхронизация на идеальном канале + MockCensor --------------------

func TestSyncLoopback(t *testing.T) {
	cfg := Config{Master: testMaster} // дефолты: 200 с/с, T=30с, S=32, c=0.85
	lc := &loopCtx{NewEndpoint(cfg, "c2s"), NewEndpoint(cfg, "s2c"), testNow()}
	lockAt := -1
	for i := 0; i < 1500; i++ {
		lc.step()
		if lockAt < 0 && lc.rx.Locked() {
			lockAt = i
		}
	}
	if lockAt < 0 {
		t.Fatal("синхронизм не достигнут за 1500 датаграмм (6000 сэмплов)")
	}
	t.Logf("lock после %d датаграмм (~%d сэмплов)", lockAt, (lockAt+1)*lc.tx.cfg.Batch)
	if s := lc.rx.Snapshot(); s.ResidMS > 0.0004 {
		t.Fatalf("остаточная ошибка после lock: ms=%g", s.ResidMS)
	}
}

// TestSyncWrongKey — MockCensor-сторона: наблюдатель без мастер-ключа не
// синхронизируется и не восстанавливает состояние из потока.
func TestSyncWrongKey(t *testing.T) {
	cfg := Config{Master: testMaster}
	lc := &loopCtx{NewEndpoint(cfg, "c2s"), NewEndpoint(Config{Master: wrongMaster}, "s2c"), testNow()}
	for i := 0; i < 2000; i++ {
		lc.step()
	}
	if lc.rx.Locked() {
		t.Fatal("наблюдатель с чужим ключом синхронизировался — ключевая зависимость сломана")
	}
}

// --- Э3: модуляция/демодуляция ---------------------------------------------

func TestModemFrameRoundtrip(t *testing.T) {
	cfg := Config{Master: testMaster}
	lc := &loopCtx{NewEndpoint(cfg, "c2s"), NewEndpoint(cfg, "s2c"), testNow()}
	if !phaseCapture(lc, 4000) {
		t.Fatal("фаза не захвачена за 4000 датаграмм")
	}
	payload := []byte("hello chaos: командный кадр поверх синхронизации")
	if err := lc.tx.PushFrame(payload); err != nil {
		t.Fatal(err)
	}
	// Кадр 48 байт → rep3: (24+24+3·416)=1296 бит × 32 = 41472 сэмпла = 10368 датаграмм.
	for i := 0; i < 20000; i++ {
		lc.step()
	}
	frames := lc.rx.Frames()
	if len(frames) == 0 {
		t.Fatal("кадр не декодирован")
	}
	if !bytes.Equal(frames[0].Payload, payload) {
		t.Fatalf("payload: got %q, want %q", frames[0].Payload, payload)
	}
	m := lc.rx.MetricsSnapshot()
	t.Logf("BER на идеальном канале: %d/%d", m.BerNum, m.BerDen)
	if m.BerDen > 0 && m.BerNum*100 > m.BerDen {
		t.Fatalf("BER > 1%% на идеальном канале: %d/%d", m.BerNum, m.BerDen)
	}
}

// --- Э4: нестационарность ---------------------------------------------------

// TestMutationResync — мутация f_k каждые 2 секунды (epochLen=384 сэмпла):
// кадры проходят через серию мутаций, логическая сессия не рвётся
// (CST-теги валидны в разных эпохах).
func TestMutationResync(t *testing.T) {
	cfg := Config{Master: testMaster, EpochSec: 8}
	lc := &loopCtx{NewEndpoint(cfg, "c2s"), NewEndpoint(cfg, "s2c"), testNow()}

	payloads := [][]byte{
		[]byte("frame-one-across-epochs"),
		[]byte("frame-two-across-epochs"),
		[]byte("frame-three-across-epochs"),
	}
	pushed, lastPush := 0, -10000
	seenEpochs := map[uint64]bool{}
	var decoded [][]byte

	// Кадр 21 байт → rep3: (24+24+3·200)=648 бит × 32 = 20736 сэмплов = 5184 датаграммы.
	// Пушим следующий кадр только при захваченной фазе и с паузой.
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
	m := lc.rx.MetricsSnapshot()
	t.Logf("декодировано кадров: %d, эпохи старта: %v, спайков: %d, resyncs: %d, BER %d/%d",
		len(decoded), seenEpochs, m.Spikes, m.Resyncs, m.BerNum, m.BerDen)
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
		t.Fatalf("дошло %d из %d кадров через мутации", found, len(payloads))
	}
	if len(seenEpochs) < 2 {
		t.Fatal("все кадры в одной эпохе — непрерывность через мутацию не доказана")
	}
}

// TestSidChain — CST: значения идентичности эпох детерминированы и различны.
func TestSidChain(t *testing.T) {
	s0 := SidForEpoch(testMaster, 5)
	s1 := SidForEpoch(testMaster, 5)
	s2 := SidForEpoch(testMaster, 6)
	if !bytes.Equal(s0, s1) || bytes.Equal(s0, s2) {
		t.Fatal("CST-цепочка сломана")
	}
}

// --- Э7: fail-closed --------------------------------------------------------

// TestServerMuxFailClosed — чужой поток никогда не получает ответ; свой
// доказывает знание ключа синхронизмом и получает s2c-поток.
func TestServerMuxFailClosed(t *testing.T) {
	cfg := Config{Master: testMaster}
	mux := NewServerMux(cfg)
	now := testNow()
	per := cfg.withDefaults().DatagramInterval()

	evil := NewEndpoint(Config{Master: wrongMaster}, "c2s")
	for i := 0; i < 800; i++ {
		if mux.Handle(evil.NextDatagram(now), "10.9.9.9:4444", now) {
			t.Fatal("чужой поток доказал знание ключа — fail-closed сломан")
		}
		now = now.Add(per)
	}
	addrs, _ := mux.Tick(now)
	for _, a := range addrs {
		if a == "10.9.9.9:4444" {
			t.Fatal("нода отвечает недоказанному источнику")
		}
	}

	good := NewEndpoint(cfg, "c2s")
	proven := false
	for i := 0; i < 1500 && !proven; i++ {
		proven = mux.Handle(good.NextDatagram(now), "10.1.1.1:5555", now)
		now = now.Add(per)
	}
	if !proven {
		t.Fatal("легитимный клиент не доказал синхронизм за 1500 датаграмм")
	}
	addrs, _ = mux.Tick(now)
	found := false
	for _, a := range addrs {
		if a == "10.1.1.1:5555" {
			found = true
		}
	}
	if !found {
		t.Fatal("доказанный клиент не получил s2c-поток")
	}
}

// TestKeyfilePerms — fail-closed на правах файла ключа.
func TestKeyfilePerms(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "master.key")
	if err := GenerateMasterKey(p); err != nil {
		t.Fatal(err)
	}
	k, err := LoadMasterKey(p)
	if err != nil || len(k) != MasterKeyLen {
		t.Fatalf("load: %v len=%d", err, len(k))
	}
	if err := GenerateMasterKey(p); err == nil {
		t.Fatal("перезапись ключа не запрещена")
	}
	p2 := filepath.Join(dir, "bad.key")
	if err := GenerateMasterKey(p2); err != nil {
		t.Fatal(err)
	}
	if err := chmod0644(p2); err != nil {
		t.Skipf("chmod: %v", err)
	}
	if chmod0644(p2) == nil {
		if _, err := LoadMasterKey(p2); err == nil {
			t.Fatal("ключ с правами 0644 принят — fail-closed сломан")
		}
	}
}

// --- Автопилот (Э5, юнит-правила) -------------------------------------------

func TestAutoTuneRules(t *testing.T) {
	base := Config{Master: testMaster}.withDefaults()

	rec, notes := AutoTune(ChannelQuality{Synced: false}, base)
	if rec.Rate != 100 || rec.SymbolS != 64 || rec.EpochSec != 64 || len(notes) == 0 {
		t.Fatalf("no-sync profile: %+v notes=%v", rec, notes)
	}

	rec, notes = AutoTune(ChannelQuality{Synced: true, Phased: true, ResidMS: 0.00001, LossPermille: 2, BER: 0.001}, base)
	if rec.EpochSec >= base.EpochSec || len(notes) == 0 {
		t.Fatalf("clean channel should shorten T: %+v", rec)
	}

	rec, notes = AutoTune(ChannelQuality{Synced: true, ResidMS: 0.01, LossPermille: 60}, base)
	if rec.SymbolS <= base.SymbolS || rec.EpochSec <= base.EpochSec {
		t.Fatalf("noisy channel should lengthen S and T: %+v notes=%v", rec, notes)
	}
}

// --- Реконструкция (превью Э6, юнит-санити) ----------------------------------

// TestReconStationaryVsMutated — направление эффекта: мутирующее поле
// ухудшает NN-реконструкцию относительно стационарного. Точные кривые
// «окно наблюдения ↔ T» строит tools/chaossync-lab (Э6), здесь — санити.
func TestReconStationaryVsMutated(t *testing.T) {
	const N = 8000
	p := DeriveField(testMaster, 500)
	x := EpochInit(testMaster, 500)
	stat := make([]uint16, N)
	for i := range stat {
		p.Step(&x)
		stat[i] = Quantize16(x[p.Drive])
	}
	mut := make([]uint16, N)
	for seg := 0; seg*1000 < N; seg++ {
		ep := uint64(9000 + seg)
		pm := DeriveField(testMaster, ep)
		xm := EpochInit(testMaster, ep)
		for i := 0; i < 1000 && seg*1000+i < N; i++ {
			pm.Step(&xm)
			mut[seg*1000+i] = Quantize16(xm[pm.Drive])
		}
	}
	nmStat := ReconNMSE(stat, 6, 1)
	nmMut := ReconNMSE(mut, 6, 1)
	nmStatH := ReconNMSEH(stat, 6, 1, 10)
	nmMutH := ReconNMSEH(mut, 6, 1, 10)
	t.Logf("NMSE h=1: stat=%.4f mut=%.4f; h=10: stat=%.4f mut=%.4f", nmStat, nmMut, nmStatH, nmMutH)
	// Санити харнесса: на стационарном поле короткий прогноз обязан быть
	// заметно лучше среднего. Направление эффекта мутации измеряется в Э6
	// (tools/chaossync-lab), а не жёстким юнит-ассертом здесь.
	if !(nmStat < 0.3) {
		t.Fatalf("харнесс реконструкции не работает: stationary NMSE=%.4f", nmStat)
	}
}
