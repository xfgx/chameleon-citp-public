package chaossync

// session.go — движок звена: TX-осциллятор и RX-наблюдатель Pecora–Carroll.
//
// Модель времени, фазы и границ эпох (v5, по итогам тестов 2026-08-30):
//   - TX: счётчик сэмплов эпохи; граница — по счётчику (epochLen, кратно S);
//     стартовая эпоха — от Unix-времени. Требование: NTP-скьюк ≪ T.
//   - Первые syncWinK=8 окон каждой эпохи — ключевая sync-преамбула (начало
//     PN-потока эпохи). Кадры СТАРТУЮТ не раньше окна syncWinK; внутриэпохный
//     кадр приостанавливается на sync-окнах следующей эпохи. Поэтому вердикт
//     о границе ВСЕГДА имеет ключевое слово для проверки.
//   - RX детектирует границу по сигналу: спайк residual (|r| > 0.10 — выше
//     любых транзиентов модуляции < 0.03), серия превышений 0.03, или
//     номинальный счётчик (быстрый путь). Затем replay-поиск фазы j по
//     кольцевому буферу сэмплов: каждая гипотеза воспроизводит наблюдателя
//     (с коррекциями) от EpochInit новой эпохи. Префильтр по residual,
//     ВЕРДИКТ — по sync-преамбуле (обязателен: принятие без него
//     запрещено — устраняет ложные принятия, найденные тестами v3/v4).
//   - Ноль кандидатов = ложный спайк: поле НЕ меняем, перезахвата нет.

import (
	"fmt"
	"math/bits"
	"sync"
	"time"
)

// Состояния RX.
const (
	rxHunt  = iota // поиск поля: параллельные наблюдатели на {m-1, m, m+1}
	rxTrack        // поле захвачено; phaseKnown = известна фаза (окна/PN)
)

// Пороги (Q16.48). Уровни на идеальном канале (измерено свипами):
//
//	синхронизм+модуляция:  residual ms ≈ 1.5e-5, |r| ≲ 0.01 (транзиенты < 0.03)
//	чужое поле:            residual ms ≈ 1e-2,  |r| ~ 0.05..0.5
//	спайк границы эпохи:   |r| ~ U[0, 0.6]
var (
	syncMsThresh   = MustDecimal("0.00005") // вход в синхронизм
	desyncMsThresh = MustDecimal("0.0005")  // выход по среднеквадратичной ошибке
	spikeThresh    = MustDecimal("0.10")    // спайк границы: выше транзиентов модуляции
	highRunThresh  = MustDecimal("0.03")    // серия превышений = дивергенция
	confirmThresh  = MustDecimal("0.02")    // префильтр replay-гипотез (вердикт — sync-слово)
)

const (
	huntWindow      = 64   // сэмплов оценки кандидата / оконная статистика
	huntPromoteGood = 3    // окон подряд ниже syncMsThresh для промоушена (fail-closed)
	huntGiveup      = 2048 // ≫ конвергенция кандидата из EpochInit (~512 по probeWarm) +
	// huntPromoteGood окон: 512 сбрасывало кандидатов ровно в момент
	// сходимости — ре-захват среди эпохи стоял до границы (2026-09-01)
	maxGapSteps  = 64 // макс. free-run шагов по одному разрыву
	desyncStreak = 192
	berWatchN    = 256 // бит PN в окне BER-сторожа
	berWatchBad  = 64  // >25% ошибок → фаза/поле потеряны
	replayW      = 64  // глубина кольцевого буфера принятых сэмплов
	syncWinK     = 8   // окон ключевой sync-преамбулы в начале каждой эпохи
)

// Config — параметры звена. Rate, EpochSec, SymbolS, Delta, Coupling и
// Master ОБЯЗАНЫ совпадать на обеих сторонах: совпадение конфигурации и
// есть скрытая аутентификация (чужие сэмплы не дают синхронизма).
type Config struct {
	Master   []byte // мастер-ключ звена (из файла, 0600; НЕ из argv)
	Rate     int    // сэмплов/сек, 50..4000 (по умолч. 200)
	EpochSec uint64 // T — период мутации f_k, секунд (по умолч. 32)
	Coupling Fxp    // c — параметр связи Pecora–Carroll (по умолч. 0.85)
	SymbolS  int    // S — сэмплов на символ для CSK (по умолч. 32)
	Delta    Fxp    // δ — амплитуда возмущения (по умолч. 2^-8; в M8 — полуразмах созвездия)
	Batch    int    // сэмплов на UDP-датаграмму, 1..8 (по умолч. 4)
	// Modulation — физический слой символа: ModulationM8 (дефолт, ~×83 к CSK
	// по Э-B) или ModulationCSK (fallback на деградацию канала).
	Modulation Modulation
	// M8S — сэмплов на символ в режиме M8 (по умолч. m8DefaultS — подобрано
	// замером символьного BER против запаса rep3-FEC, m8_test.go/agent.md).
	M8S int
}

func (c Config) withDefaults() Config {
	if c.Rate <= 0 {
		c.Rate = 200
	}
	if c.Rate > 4000 {
		c.Rate = 4000
	}
	if c.EpochSec == 0 {
		c.EpochSec = 32
	}
	if c.Coupling == 0 {
		c.Coupling = MustDecimal("0.85")
	}
	if c.SymbolS <= 0 {
		c.SymbolS = 32
	}
	if c.Delta == 0 {
		c.Delta = Fxp(oneRaw >> 8) // 2^-8 ≈ 0.0039
	}
	if c.Batch <= 0 {
		c.Batch = 4
	}
	if c.Batch > 8 {
		c.Batch = 8
	}
	if c.Modulation == ModulationM8 && c.M8S <= 0 {
		c.M8S = m8DefaultS
	}
	return c
}

// symParams — бит на символьное окно и сэмплов на окно активной модуляции:
// M8 → (3, M8S), CSK → (1, SymbolS).
func (c Config) symParams() (bps, symS int) {
	d := c.withDefaults()
	if d.Modulation == ModulationCSK {
		return 1, d.SymbolS
	}
	return 3, d.M8S
}

// epochLen — сэмплов в эпохе. ОБЯЗАНО быть кратным числу сэмплов на символ
// активной модуляции (см. Validate).
func (c Config) epochLen() uint64 { d := c.withDefaults(); return uint64(d.Rate) * d.EpochSec }

// Validate — fail-closed проверка конфигурации звена.
func (c Config) Validate() error {
	bps, symS := c.symParams()
	if symS < 1 || symS > 128 {
		return fmt.Errorf("chaossync: сэмплов на символ %d вне [1,128]", symS)
	}
	if uint64(c.Rate)*c.EpochSec%uint64(symS) != 0 {
		return fmt.Errorf("chaossync: rate*epochSec=%d не кратно symbolS=%d — подберите T кратно %g с",
			uint64(c.Rate)*c.EpochSec, symS, float64(symS)/float64(c.Rate))
	}
	if uint64(c.Rate)*c.EpochSec/uint64(symS) < 2*syncWinK {
		return fmt.Errorf("chaossync: в эпохе меньше %d окон — sync-преамбула не оставляет места данным", 2*syncWinK)
	}
	if bps == 3 && uint64(c.Rate)*c.EpochSec/uint64(symS) < m8RegionWin+syncWinK {
		return fmt.Errorf("chaossync: в эпохе меньше %d окон — sync-регион M8 не оставляет места данным", m8RegionWin+syncWinK)
	}
	return nil
}

// Interval — период одного сэмпла.
func (c Config) Interval() time.Duration { return time.Second / time.Duration(c.withDefaults().Rate) }

// DatagramInterval — ожидаемый период датаграмм.
func (c Config) DatagramInterval() time.Duration {
	d := c.withDefaults()
	return time.Second / time.Duration(d.Rate) * time.Duration(d.Batch)
}

// Metrics — счётчики звена (весь доступ под мьютексом Endpoint).
type Metrics struct {
	TxSamples    uint64
	RxSamples    uint64
	InferredLoss uint64
	Resyncs      uint64 // полные перезахваты поля (hunt)
	Spikes       uint64 // принятые границы эпох (sync-вердикт пройден)
	FalseSpikes  uint64 // спайки без кандидатов (транзиенты) — без перезахвата
	FramesOK     uint64
	FramesBadTag uint64
	FramesBadCRC uint64
	BerNum       uint64
	BerDen       uint64
	SyncBad      uint64 // sync-окна с ошибкой (ключевое слово не сошлось)
	SyncTot      uint64
}

// huntObs — кандидат захвата на одну эпоху.
type huntObs struct {
	epoch uint64
	p     *FieldParams
	x     [Sites]Fxp
	ms    Fxp
	n     int
	good  int // подряд окон ниже syncMsThresh (промоушен при huntPromoteGood)
}

// boundaryCand — кандидат на границу эпохи: поле/состояние новой эпохи и
// residual'ы её сэмплов с момента границы (replay с коррекциями).
type boundaryCand struct {
	epoch     uint64
	p         *FieldParams
	x         [Sites]Fxp
	verdictOK bool  // M8: скользящий кворум-вердикт пройден
	resid     []Fxp // residual сэмпла k новой эпохи — в resid[k]
}

// rxQItem — элемент джиттер-буфера: сэмпл ИЛИ метка разрыва канала
// (по счётчику последовательности датаграмм). Разрыв — не сэмпл: free-run.
type rxQItem struct {
	v    uint16
	hole bool
}

// Endpoint — двусторонняя точка звена.
type Endpoint struct {
	cfg  Config
	txM  []byte
	rxM  []byte
	mod  Modulator // CSK-слой (fallback)
	m8   Modem8    // M8-слой (дефолт по Э-B)
	bps  int       // бит на символьное окно: 3 (M8) | 1 (CSK)
	symS int       // сэмплов на символьное окно: M8S (M8) | SymbolS (CSK)

	mu sync.Mutex

	// TX
	txEpoch   uint64
	txParams  *FieldParams
	txX       [Sites]Fxp
	txCount   uint64
	enc       *frameEncoder
	lastSym   uint64
	lastBit   bool
	lastSymV  uint8 // последний выбранный символ окна (M8)
	lastSymOK bool
	txIdle    []uint8 // кэш PN-символов эпохи (только M8; CSK берёт IdleBit лениво)

	// RX
	mode        int // rxHunt | rxTrack
	phaseKnown  bool
	rxEpoch     uint64
	rxParams    *FieldParams
	rxX         [Sites]Fxp
	rxCount     uint64 // сэмплов с последней принятой границы
	hunt        [3]*huntObs
	huntN       int
	huntInit    bool
	msSum       Fxp
	msN         int
	lastMs      float64
	desyncN     int
	desyncGrace int // остатковый грейс-период после перехода эпохи (сэмплы)
	berWin      uint64
	berWinBad   uint64
	lastArr     time.Time
	hasArr      bool
	lastNow     time.Time
	jitSumMs    float64
	jitN        uint64
	symAcc      Fxp
	highRun     int // подряд сэмплов с |r| > highRunThresh
	parser      *frameParser
	frames      []ParsedFrame
	pnBits      []bool
	pnEpoch     uint64
	pnOK        bool
	ybuf        [replayW]Fxp
	yTotal      uint64
	yValid      int
	rxQ         []rxQItem // джиттер-буфер сэмплов (Э5, buffered path; hole=разрыв)
	txSeq       byte      // счётчик исходящих датаграмм (mod 256)
	rxSeq       byte      // последний принятый счётчик
	rxSeqOK     bool      // был ли принят хоть один пакет
	gapMute     int       // окон приглушения BER-учёта после разрыва (M8)

	// pending-верификация границы (ждём sync-преамбулу)
	pendOn    bool
	pendCands []boundaryCand
	pendOld   []Fxp // residual'ы старого поля во время pending (для отката)
	pendPN    []bool

	m Metrics
}

// NewEndpoint — новая точка. txDir = "c2s" (клиент) или "s2c" (нода).
func NewEndpoint(cfg Config, txDir string) *Endpoint {
	// M8: дефолт связи наблюдателя c=0.95 (по замеру 2026-09-01 — см. modem.go
	// и agent.md). Делается ДО withDefaults и только здесь: withDefaults
	// обязан оставаться режим-нейтральным (SelftestVector гейта Э1 использует
	// его напрямую и живёт на историческом дефолте 0.85).
	if cfg.Modulation == ModulationM8 && cfg.Coupling == 0 {
		cfg.Coupling = m8DefaultCoupling
	}
	cfg = cfg.withDefaults()
	if err := cfg.Validate(); err != nil {
		panic(err) // fail-closed: невалидная конфигурация — программная ошибка
	}
	rxDir := "c2s"
	if txDir == "c2s" {
		rxDir = "s2c"
	}
	bps, symS := cfg.symParams()
	return &Endpoint{
		cfg:    cfg,
		txM:    dirMaster(cfg.Master, txDir),
		rxM:    dirMaster(cfg.Master, rxDir),
		mod:    Modulator{Delta: cfg.Delta, S: cfg.SymbolS},
		m8:     NewModem8(cfg.Delta, symS),
		bps:    bps,
		symS:   symS,
		enc:    newFrameEncoder(),
		parser: newFrameParser(),
		mode:   rxHunt,
	}
}

// PushFrame ставит полезную нагрузку (1..200 байт) в очередь модуляции.
func (e *Endpoint) PushFrame(payload []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.enc.Push(payload)
}

// Frames забирает проверенные входящие кадры (CST-тег валиден).
func (e *Endpoint) Frames() []ParsedFrame {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.frames) == 0 {
		return nil
	}
	out := make([]ParsedFrame, len(e.frames))
	copy(out, e.frames)
	e.frames = e.frames[:0]
	return out
}

// Locked — true, когда наблюдатель захватил поле (доказано знание ключа).
func (e *Endpoint) Locked() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.mode == rxTrack
}

// MetricsSnapshot — копия счётчиков.
func (e *Endpoint) MetricsSnapshot() Metrics {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.m
}

// --- TX ------------------------------------------------------------------

// NextDatagram — очередная датаграмма TX-осциллятора. Окна 0..syncWinK-1
// каждой эпохи несут ключевую sync-преамбулу (первые биты PN-потока эпохи);
// кадровый поток на них приостанавливается.
func (e *Endpoint) NextDatagram(now time.Time) []byte {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.txParams == nil {
		e.txEpoch = EpochFor(now, e.cfg.EpochSec)
		e.txParams = DeriveField(e.txM, e.txEpoch)
		e.txX = EpochInit(e.txM, e.txEpoch)
		e.txCount = 0
		e.txRefreshIdleLocked()
	}
	q := make([]uint16, 0, e.cfg.Batch)
	for i := 0; i < e.cfg.Batch; i++ {
		if e.txCount >= e.cfg.epochLen() {
			e.txEpoch++
			e.txParams = DeriveField(e.txM, e.txEpoch)
			e.txX = EpochInit(e.txM, e.txEpoch)
			e.txCount = 0
			e.lastSymOK = false
			e.txRefreshIdleLocked()
		}
		e.txParams.Step(&e.txX)
		symIdx := e.txCount / uint64(e.symS)
		if e.bps == 3 {
			var sym uint8
			if e.lastSymOK && symIdx == e.lastSym {
				sym = e.lastSymV
			} else {
				if symIdx < m8RegionWin {
					// sync-регион M8 (guard+вердикт): ключевое PN-слово, кадровый
					// поток не трогаем (кадр «приостанавливается» на регионе)
					sym = e.txIdle[symIdx]
				} else {
					sym = e.enc.nextSymM8(e.txM, e.txEpoch, symIdx, e.txIdle)
				}
				e.lastSym, e.lastSymV, e.lastSymOK = symIdx, sym, true
			}
			e.m8.Perturb(&e.txX, e.txParams.Drive, sym)
		} else {
			var bit bool
			if e.lastSymOK && symIdx == e.lastSym {
				bit = e.lastBit
			} else {
				if symIdx < syncWinK {
					// sync-преамбула: keyed слово, кадровый поток не трогаем
					bit = IdleBit(e.txM, e.txEpoch, symIdx)
				} else {
					bit = e.enc.nextBit(e.txM, e.txEpoch, symIdx)
				}
				e.lastSym, e.lastBit, e.lastSymOK = symIdx, bit, true
			}
			e.mod.Perturb(&e.txX, e.txParams.Drive, bit)
		}
		q = append(q, Quantize16(e.txX[e.txParams.Drive]))
		e.txCount++
	}
	e.m.TxSamples += uint64(len(q))
	// Датаграмма = [1 байт счётчика][сэмплы]. Счётчик — единственный точный
	// детектор разрывов под джиттером (по времени при ±30% джиттера разрыв
	// ошибочно округляется в ±1 окно и фаза потока едет — замер 2026-09-01).
	dat := make([]byte, 1+2*len(q))
	dat[0] = e.txSeq
	e.txSeq++
	EncodeSamples(dat[1:], q)
	return dat
}

// txRefreshIdleLocked — перегенерация кэша PN-символов эпохи на границе
// (только M8). Кэш покрывает и sync-преамбулу, и холостой поток эпохи.
func (e *Endpoint) txRefreshIdleLocked() {
	if e.bps != 3 {
		return
	}
	e.txIdle = pnSymbolsForEpoch(e.txM, e.txEpoch, e.cfg.epochLen()/uint64(e.symS), e.bps)
}

// --- RX ------------------------------------------------------------------

// HandleDatagram — обработка входящей датаграммы с оценкой разрывов.
func (e *Endpoint) HandleDatagram(dat []byte, now time.Time) {
	if len(dat) < 3 {
		return
	}
	seq := dat[0]
	var q [8]uint16
	n := DecodeSamples(dat[1:], q[:])
	if n == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.huntInit {
		e.startHuntLocked(now)
	}
	// метрика джиттера по межприходным интервалам (информационная, как было)
	if e.hasArr {
		dev := now.Sub(e.lastArr) - e.cfg.DatagramInterval()
		if dev < 0 {
			dev = -dev
		}
		e.jitSumMs += float64(dev.Microseconds()) / 1000.0
		e.jitN++
	}
	e.lastArr, e.hasArr = now, true
	e.lastNow = now
	// Разрыв — по счётчику последовательности (mod 256, со знаком):
	// дубликат/переупорядочивание отбрасываем, пропуск компенсируем точно.
	missed := 0
	if e.rxSeqOK {
		delta := int(int8(seq - e.rxSeq - 1))
		if delta < 0 {
			return // дубликат или опоздавший из прошлого — не дважды
		}
		if delta > maxGapSteps {
			delta = maxGapSteps
		}
		missed = delta * e.cfg.Batch
	}
	e.rxSeq, e.rxSeqOK = seq, true
	if missed > 0 {
		e.m.InferredLoss += uint64(missed)
		// Разрыв: free-run без коррекции; replay-буфер инвалиден через разрыв.
		e.yValid = 0
		if e.bps == 3 {
			// M8: фазу НЕ роняем — разрыв компенсирован ровно missed сэмплов по
			// счётчику (окна выровнены: Batch == S), окна разрыва коммитятся
			// эразуром (rxFreeRunLocked), наблюдатель сходится за 0-1 окна (замер).
			// Окна разрыва и восстановления — вне BER-учёта.
			e.gapMute += missed/e.symS + m8GapMuteWin
			if e.pendOn {
				e.pendGapLocked(missed)
			}
		} else {
			// CSK: pending через разрыв не верифицируется — откат как при ложном спайке.
			if e.pendOn {
				e.flushPendingFalseLocked()
			}
			e.phaseKnown = false // счётчик сбит разрывом — граница снова по спайку
		}
		for j := 0; j < missed; j++ {
			e.rxFreeRunLocked()
		}
	}
	for i := 0; i < n; i++ {
		e.rxSampleLocked(Dequantize16(q[i]), now)
	}
}

// startHuntLocked — (пере)запуск захвата: кандидаты на эпохи {m-1, m, m+1}.
func (e *Endpoint) startHuntLocked(now time.Time) {
	if e.huntInit {
		e.m.Resyncs++ // первичный захват — не ресинк
	}
	m := EpochFor(now, e.cfg.EpochSec)
	for i := 0; i < 3; i++ {
		ep := m + uint64(i) - 1
		e.hunt[i] = &huntObs{
			epoch: ep,
			p:     DeriveField(e.rxM, ep),
			x:     EpochInit(e.rxM, ep),
		}
	}
	e.huntN = 0
	e.huntInit = true
	e.mode = rxHunt
	e.phaseKnown = false
	e.rxParams = nil
	e.msSum, e.msN, e.desyncN = 0, 0, 0
	e.symAcc = 0
	e.highRun = 0
	e.berWin, e.berWinBad = 0, 0
	e.pnOK = false
	e.pendOn = false
	e.pendCands = nil
	e.pendOld = nil
	e.parser.Reset() // кадр в сборке мёртв — маркер найдёт следующий
}

// rxFreeRunLocked — свободный шаг без коррекции (потерянный сэмпл).
func (e *Endpoint) rxFreeRunLocked() {
	if e.mode == rxHunt {
		for _, c := range e.hunt {
			c.p.Step(&c.x)
		}
		return
	}
	// свободный бег через разрыв: счётчик и границы эпох идут дальше,
	// поле ре-синхронизируется сбросом в EpochInit на ближайшей границе.
	if e.phaseKnown && e.rxCount >= e.cfg.epochLen() {
		e.adoptNextEpochLocked()
	}
	e.rxParams.Step(&e.rxX)
	// M8: окно, завершившееся в разрыве, коммитим, а не пропускаем — позиции
	// бит кадра сохраняются, иначе кадр сдвигается и умирает по CRC на любом
	// разрыве (замер 2026-09-01: при 1% потерь 100% кадров умирало). В idle
	// коммитим ОЖИДАЕМЫЙ PN-символ (он ключевой, провод не нужен — сторож BER
	// не будим), в кадре — нейтральный ноль: поблочно-перемежённые rep3-копии
	// по обе стороны разрыва его перекрывают. Символ кадра маркера, попавший в
	// разрыв, теряет кадр — следующий маркер поймается (как у CSK по ТО-же
	// семействе семантики; CSK-путь не меняется).
	if e.bps == 3 && e.phaseKnown && (e.rxCount%uint64(e.symS)) == uint64(e.symS)-1 {
		symIdx := e.rxCount / uint64(e.symS)
		sym := uint8(0)
		if !e.parser.InFrame() && e.pnOK && (symIdx+1)*3 <= uint64(len(e.pnBits)) {
			sym = pnWindowSym(e.pnBits, symIdx, 3)
		}
		e.commitWindowLocked(sym, symIdx, e.rxEpoch)
	}
	e.rxCount++
}

// rxQCap — граница джиттер-буфера (сэмплов). ~2 секунды при rate=200.
const rxQCap = 8192

// EnqueueDatagram — приём с джиттер-буфером (Э5): декодирует датаграмму и
// ставит сэмплы в очередь БЕЗ немедленной обработки. Обработка идёт в TickRx
// по ЛОКАЛЬНЫМ часам приёмника — это отделяет часы сэмплов от джиттера сети.
// Джиттер прихода здесь — только метрика качества канала (DPI-профиль),
// а не сигнал потери. Потеря — это underrun очереди в TickRx.
func (e *Endpoint) EnqueueDatagram(dat []byte, now time.Time) {
	if len(dat) < 3 {
		return
	}
	seq := dat[0]
	var q [8]uint16
	n := DecodeSamples(dat[1:], q[:])
	if n == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	// метрика джиттера по межприходным интервалам (информационная)
	if e.hasArr {
		per := e.cfg.DatagramInterval()
		dev := now.Sub(e.lastArr) - per
		if dev < 0 {
			dev = -dev
		}
		e.jitSumMs += float64(dev.Microseconds()) / 1000.0
		e.jitN++
	}
	e.lastArr, e.hasArr = now, true
	// Разрыв — по счётчику: метки hole в очередь (TickRx free-run'ит их по
	// локальным часам — фаза потока и часовая сетка не расходятся).
	if e.rxSeqOK {
		delta := int(int8(seq - e.rxSeq - 1))
		if delta < 0 {
			return // дубликат/опоздавший
		}
		if delta > maxGapSteps {
			delta = maxGapSteps
		}
		if e.bps == 3 {
			e.gapMute += delta*(e.cfg.Batch/e.symS) + m8GapMuteWin // см. выше
		}
		for j := 0; j < delta*e.cfg.Batch; j++ {
			e.rxQ = append(e.rxQ, rxQItem{hole: true})
		}
	}
	e.rxSeq, e.rxSeqOK = seq, true
	for i := 0; i < n; i++ {
		e.rxQ = append(e.rxQ, rxQItem{v: q[i]})
	}
	if len(e.rxQ) > rxQCap {
		e.rxQ = e.rxQ[len(e.rxQ)-rxQCap:]
	}
}

// TickRx — один такт локальных часов приёмника: обработать Batch сэмплов из
// джиттер-буфера. Вызывается драйвером с периодом DatagramInterval().
// Underrun (очередь пуста) = реальный разрыв: free-run, счётчик остаётся
// выровненным, поле ре-синхронизируется на ближайшей границе эпохи.
// TickRx — один такт локальных часов приёмника: обработать сэмплы из
// джиттер-буфера ПО ПОРЯДКУ. Вызывается драйвером с периодом DatagramInterval().
//
// Пустая очередь — джиттер (датаграмма ещё в пути), а НЕ потеря: поле шагаем
// ТОЛЬКО по реальным сэмплам, счётчик/фаза не сдвигаются. Поле дискретно по
// индексу сэмпла, а не по стенке — пауза безопасна и НЕ ломает выравнивание.
// Реальная потеря вскрывается residual'ом (resync), а каждая эпоха и так
// сбрасывает обе стороны в EpochInit — переходный сбой лечится сам.
func (e *Endpoint) TickRx(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.huntInit {
		e.startHuntLocked(now)
	}
	// Догоняем бэклог после всплеска: до 2*Batch за такт, если очередь длинная.
	limit := e.cfg.Batch
	if len(e.rxQ) > 2*e.cfg.Batch {
		limit = 2 * e.cfg.Batch
	}
	for i := 0; i < limit && len(e.rxQ) > 0; i++ {
		it := e.rxQ[0]
		e.rxQ = e.rxQ[1:]
		if it.hole {
			e.rxFreeRunLocked()
			continue
		}
		e.rxSampleLocked(Dequantize16(it.v), now)
	}
}

// RxQueued — текущая глубина джиттер-буфера (сэмплы). Метрика канала.
func (e *Endpoint) RxQueued() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.rxQ)
}

// huntStepLocked — шаг захвата. Захват даёт только ПОЛЕ: фаза неизвестна до
// первой принятой границы эпохи.
func (e *Endpoint) huntStepLocked(y Fxp, now time.Time) {
	promoted := -1
	for i, c := range e.hunt {
		r := c.p.ObserverStep(&c.x, y, e.cfg.Coupling)
		c.ms = c.ms.Add(r.Mul(r))
		c.n++
		if c.n >= huntWindow {
			avg := Fxp(int64(c.ms) / int64(c.n))
			// Промоушен — только после huntPromoteGood ПОДРЯД окон ниже порога:
			// при c=0.95 чужое поле измерено способно на ОДНОМ окне провалиться до
			// 4.7e-5 < 5e-5 (редкое совпадение траекторий, 2026-09-01) — серия из 3
			// его отсекает; честному замку (7e-6 M8 / 1.4e-5 CSK, устойчиво) серия
			// не мешает, цена — до +128 сэмплов к захвату.
			if avg < syncMsThresh {
				c.good++
				if c.good >= huntPromoteGood {
					promoted = i
				}
			} else {
				c.good = 0
			}
			c.ms, c.n = 0, 0
		}
	}
	e.huntN++
	if promoted >= 0 {
		c := e.hunt[promoted]
		e.rxEpoch = c.epoch
		e.rxParams = c.p
		e.rxX = c.x
		e.rxCount = 0
		e.mode = rxTrack
		e.phaseKnown = false
		e.msSum, e.msN, e.desyncN = 0, 0, 0
		e.symAcc = 0
		e.pnOK = false
		return
	}
	if e.huntN >= huntGiveup {
		e.huntN = 0
		m := EpochFor(now, e.cfg.EpochSec)
		for i := 0; i < 3; i++ {
			ep := m + uint64(i) - 1
			e.hunt[i] = &huntObs{epoch: ep, p: DeriveField(e.rxM, ep), x: EpochInit(e.rxM, ep)}
		}
	}
}

// pushSampleLocked — положить принятый сэмпл в кольцевой буфер.
func (e *Endpoint) pushSampleLocked(y Fxp) {
	e.yTotal++
	e.ybuf[e.yTotal%replayW] = y
	if e.yValid < replayW {
		e.yValid++
	}
}

// sampleAt — сэмпл с абсолютным индексом idx из кольцевого буфера.
func (e *Endpoint) sampleAt(idx uint64) (Fxp, bool) {
	if idx == 0 || idx > e.yTotal || e.yTotal-idx >= uint64(e.yValid) {
		return 0, false
	}
	return e.ybuf[idx%replayW], true
}

// rxSampleLocked — один принятый сэмпл (уже деквантованный).
func (e *Endpoint) rxSampleLocked(y Fxp, now time.Time) {
	e.m.RxSamples++
	e.pushSampleLocked(y)
	if e.mode == rxHunt {
		e.huntStepLocked(y, now)
		return
	}
	if e.pendOn {
		e.pendStepLocked(y)
		return
	}

	// Штатная граница эпохи — по выровненному захватом счётчику (фаза
	// известна): детерминированный переход, идентичный TX (та же эпоха, то же
	// EpochInit, тот же счётчик окон). Без спайка и replay: обе стороны
	// сбрасываются в одно состояние в один сэмпл — нулевой транзиент.
	if e.phaseKnown && e.rxCount >= e.cfg.epochLen() {
		e.adoptNextEpochLocked()
	}

	p := e.rxParams
	p.Step(&e.rxX)
	pred := e.rxX[p.Drive]
	r := y.Sub(pred)

	if r.Abs() > highRunThresh {
		e.highRun++
	} else {
		e.highRun = 0
	}
	// Спайк-детекция границы — только при неизвестной фазе (первичный захват
	// фазы либо перезахват после потерь на канале). В штатном режиме граница
	// уходит по счётчику и спайк-логика не задействована.
	if !e.phaseKnown && (r.Abs() > spikeThresh || e.highRun >= 3) {
		if e.startBoundaryCheckLocked(r) {
			return // граница принята или pending запущен — сэмпл поглощён
		}
		// иначе — ложный спайк: продолжаем старое поле БЕЗ перезахвата.
	}
	// Штатная коррекция.
	e.rxX[p.Drive] = pred.Add(e.cfg.Coupling.Mul(r))

	// Оконная статистика качества (residual ms).
	if e.desyncGrace > 0 {
		e.desyncGrace--
	}
	e.msSum = e.msSum.Add(r.Mul(r))
	e.msN++
	if e.msN >= huntWindow {
		avg := Fxp(int64(e.msSum) / int64(e.msN))
		e.lastMs = fxpToFloat(avg)
		if e.desyncGrace > 0 {
			// пограничный транзиент слежения — не рассинхрон: поле ре-конвергирует
		} else if avg > desyncMsThresh {
			e.desyncN += e.msN
		} else {
			e.desyncN = 0
		}
		e.msSum, e.msN = 0, 0
		if e.desyncN >= desyncStreak {
			e.startHuntLocked(now)
			return
		}
	}

	if e.phaseKnown {
		e.rxDecodeSymbolLocked(r) // декод с индексом ТЕКУЩЕГО сэмпла
	}
	e.rxCount++
}

// adoptNextEpochLocked — детерминированный переход на следующую эпоху по
// выровненному счётчику: идентично TX (та же эпоха, то же EpochInit). Фаза
// остаётся известной; sync-преамбула новой эпохи верифицирует переход
// (расхождение sync-слов = счётчик сбит → desync-сторож перезахватит).
func (e *Endpoint) adoptNextEpochLocked() {
	e.rxEpoch++
	e.rxParams = DeriveField(e.rxM, e.rxEpoch)
	e.rxX = EpochInit(e.rxM, e.rxEpoch)
	e.rxCount = 0
	e.symAcc = 0
	e.highRun = 0
	e.msSum, e.msN, e.desyncN = 0, 0, 0
	e.desyncGrace = syncWinK * e.symS
	if e.bps == 3 {
		e.desyncGrace = m8VerdictCapWin * e.symS // покрыть скользящий вердикт
	}
	e.pnBits = IdleBitsForEpoch(e.rxM, e.rxEpoch, e.cfg.epochLen()/uint64(e.symS)*uint64(e.bps))
	e.pnEpoch = e.rxEpoch
	e.pnOK = true
	e.m.Spikes++
}

// startBoundaryCheckLocked — строит кандидатов границы replay'ем наблюдателя
// от EpochInit(rxEpoch+1) по буферу сэмплов. Префильтр по residual, вердикт —
// sync-преамбула (первые syncWinK окон эпохи). Если преамбула уже целиком в
// буфере — решение немедленно; иначе pending до окончания преамбулы.
// Возвращает true, если сэмпл поглощён (принятие или pending).
// Ноль кандидатов = ложный спайк → false (старое поле продолжается).
func (e *Endpoint) startBoundaryCheckLocked(rCur Fxp) bool {
	ne := e.rxEpoch + 1
	p2 := DeriveField(e.rxM, ne)
	init := EpochInit(e.rxM, ne)
	pn := IdleBitsForEpoch(e.rxM, ne, e.cfg.epochLen()/uint64(e.symS)*uint64(e.bps))
	jmax := replayW
	if e.yValid < jmax {
		jmax = e.yValid
	}
	var cands []boundaryCand
	for j := 0; j < jmax; j++ {
		x := init
		ok := true
		resid := make([]Fxp, 0, j+1)
		for k := 0; k <= j; k++ {
			p2.Step(&x)
			pred := x[p2.Drive]
			yk, okBuf := e.sampleAt(e.yTotal - uint64(j) + uint64(k))
			if !okBuf {
				ok = false
				break
			}
			rk := yk.Sub(pred)
			resid = append(resid, rk)
			if rk.Abs() > confirmThresh {
				ok = false
				break
			}
			if k < j {
				x[p2.Drive] = pred.Add(e.cfg.Coupling.Mul(rk))
			}
		}
		if !ok {
			continue
		}
		last := resid[len(resid)-1]
		x[p2.Drive] = x[p2.Drive].Add(e.cfg.Coupling.Mul(last))
		cand := boundaryCand{epoch: ne, p: p2, x: x, resid: resid}
		if !e.candSyncOK(&cand, pn) {
			continue
		}
		cands = append(cands, cand)
	}
	if len(cands) == 0 {
		e.m.FalseSpikes++
		return false
	}
	// Немедленное решение только если sync-преамбула УЖЕ целиком покрыта
	// replay'ем (поздний спайк); иначе — pending до конца преамбулы.
	need := syncWinK * uint64(e.symS)
	if e.bps == 3 {
		need = uint64(m8RegionWin) * uint64(e.symS) // вердикт-зона M8 целиком
	}
	if uint64(len(cands[0].resid)) >= need {
		e.adoptCandidateLocked(&cands[0]) // вердикт полный, кандидатов ≥1
		return true
	}
	e.pendOn = true
	e.pendCands = cands
	e.pendOld = []Fxp{rCur}
	e.pendPN = pn
	return true
}

// candSyncOK — вердикт по sync-преамбуле: каждое ПОЛНОЕ окно из первых
// syncWinK обязано декодировать символ ключевого PN-потока эпохи (CSK: 1 бит;
// M8: все 3 бита — преамбула втрое сильнее при той же длине в окнах).
// Дата-окна (≥syncWinK) не проверяются — их содержимое заранее неизвестно.
func (e *Endpoint) candSyncOK(c *boundaryCand, pn []bool) bool {
	S := uint64(e.symS)
	if e.bps == 3 {
		// M8: вердикт — скользящий кворум m8Verdict по мере накопления resid
		// (вызывается из pendStepLocked); здесь кандидат всегда жив.
		return true
	}
	for w := uint64(0); w < syncWinK && (w+1)*S <= uint64(len(c.resid)); w++ {
		if (w+1)*uint64(e.bps) > uint64(len(pn)) {
			break
		}
		var acc Fxp
		for k := w * S; k < (w+1)*S; k++ {
			acc = acc.Add(c.resid[k])
		}
		if (acc > 0) != pn[w] {
			return false
		}
	}
	return true
}

// residAbsent — sentinel в resid/pendOld: сэмпл потерян разрывом канала
// (позиция сохраняется, значения нет). В интегралы не входит, окно с
// sentinel'ем вердикт не считает.
const residAbsent = Fxp(-1 << 62)

// m8GapMuteWin — окон приглушения BER-учёта ПОСЛЕ разрыва (восстановление
// наблюдателя; замер 2026-09-01: 0-1 окна). Окна самого разрыва мутятся тем
// же счётчиком (они эразур-коммитятся — измерять по ним PN-BER нечестно:
// потеря учтена в InferredLoss, а не в качестве канала).
const m8GapMuteWin = 2

// m8Verdict — скользящий sync-вердикт M8: последние m8VerdictWin полных окон
// кандидата (зона скользит от m8GuardWin до m8VerdictCapWin) — кворум
// m8VerdictQuorum совпадений с ключевым PN; окна с разрывом не считаются (но
// посчитанных минимум m8VerdictMinOK). Замер 2026-09-01 (dirMaster c2s, 512
// эпох): фиксированные зоны фейлят ~6.5% враждебных эпох (gain-экскурсии
// глубоко в эпоху), скользящий проходит их по чистому хвосту; чужое поле и
// off-by-one до вердикта не доходят (pre-filter: их max|r| ≥ 0.15 при 0.02).
func (e *Endpoint) m8Verdict(c *boundaryCand, pn []bool) bool {
	S := uint64(e.symS)
	full := uint64(len(c.resid)) / S
	if full < uint64(m8RegionWin) {
		return false // раньше конца guard+verdict региона не судим
	}
	end := full
	if end > uint64(m8VerdictCapWin) {
		end = uint64(m8VerdictCapWin)
	}
	start := end - uint64(m8VerdictWin)
	match, counted := 0, 0
	for w := start; w < end; w++ {
		if (w+1)*uint64(e.bps) > uint64(len(pn)) {
			break
		}
		var acc Fxp
		gap := false
		for k := w * S; k < (w+1)*S; k++ {
			if c.resid[k] == residAbsent {
				gap = true
				break
			}
			acc = acc.Add(c.resid[k])
		}
		if gap {
			continue
		}
		counted++
		if e.m8.Classify(acc) == pnWindowSym(pn, w, e.bps) {
			match++
		}
	}
	return counted >= m8VerdictMinOK && match >= m8VerdictQuorum
}

// pendGapLocked — M8: pending переживает разрыв канала: кандидаты free-run
// без коррекции, позиции помечаются residAbsent; старое поле free-run'ит
// вызывающий код (rxFreeRunLocked), pendOld получает sentinel'ы для
// выравнивания позиций при возможном откате.
func (e *Endpoint) pendGapLocked(missed int) {
	for i := range e.pendCands {
		c := &e.pendCands[i]
		for j := 0; j < missed; j++ {
			c.p.Step(&c.x)
			c.resid = append(c.resid, residAbsent)
		}
	}
	for j := 0; j < missed; j++ {
		e.pendOld = append(e.pendOld, residAbsent)
	}
}

// pendStepLocked — сэмпл во время pending (ждём конца sync-преамбулы).
func (e *Endpoint) pendStepLocked(y Fxp) {
	// Старое поле продолжаем (на случай ложного спайка), residual копим.
	p := e.rxParams
	p.Step(&e.rxX)
	pred := e.rxX[p.Drive]
	r := y.Sub(pred)
	e.rxX[p.Drive] = pred.Add(e.cfg.Coupling.Mul(r))
	e.pendOld = append(e.pendOld, r)

	alive := e.pendCands[:0]
	for i := range e.pendCands {
		c := &e.pendCands[i]
		c.p.Step(&c.x)
		cp := c.x[c.p.Drive]
		cr := y.Sub(cp)
		c.resid = append(c.resid, cr)
		c.x[c.p.Drive] = cp.Add(e.cfg.Coupling.Mul(cr))
		if e.bps == 3 {
			// M8: скользящий кворум-вердикт; живёт до прохода или до капа зоны
			if !c.verdictOK {
				c.verdictOK = e.m8Verdict(c, e.pendPN)
			}
			if c.verdictOK || uint64(len(c.resid))/uint64(e.symS) < uint64(m8VerdictCapWin) {
				alive = append(alive, *c)
			}
		} else if e.candSyncOK(c, e.pendPN) {
			alive = append(alive, *c)
		}
	}
	if e.bps == 3 {
		if len(alive) == 0 {
			e.flushPendingFalseLocked()
			return
		}
		// Принять лучшего из прошедших вердикт (min Σr², разрывы пропуская)
		best := -1
		var bestSum Fxp
		for i := range alive {
			if !alive[i].verdictOK {
				continue
			}
			var s Fxp
			for _, rr := range alive[i].resid {
				if rr != residAbsent {
					s = s.Add(rr.Mul(rr))
				}
			}
			if best < 0 || s.Raw() < bestSum.Raw() {
				best, bestSum = i, s
			}
		}
		if best >= 0 {
			e.adoptCandidateLocked(&alive[best])
			return
		}
		e.pendCands = alive
		return
	}
	need := syncWinK * uint64(e.symS)
	switch {
	case len(alive) == 0:
		e.flushPendingFalseLocked()
	case uint64(len(alive[0].resid)) >= need:
		// Преамбула завершена: все выжившие прошли sync-вердикт.
		// Больше одного выжившего практически невозможно; тогда — min Σr².
		best := 0
		if len(alive) > 1 {
			var bestSum Fxp
			for i := range alive {
				var s Fxp
				for _, rr := range alive[i].resid {
					s = s.Add(rr.Mul(rr))
				}
				if i == 0 || s.Raw() < bestSum.Raw() {
					best, bestSum = i, s
				}
			}
		}
		e.adoptCandidateLocked(&alive[best])
	default:
		e.pendCands = alive
	}
}

// flushPendingFalseLocked — ложный спайк: сброс pending, до-декод старым
// полем того, что накопилось за ожидание.
func (e *Endpoint) flushPendingFalseLocked() {
	e.pendOn = false
	e.pendCands = nil
	for _, ro := range e.pendOld {
		if ro == residAbsent {
			e.rxCount++ // позиция сохраняется, данных не было
			continue
		}
		if e.phaseKnown {
			e.rxDecodeSymbolLocked(ro)
		}
		e.rxCount++
	}
	e.pendOld = nil
}

// adoptCandidateLocked — принять кандидата: новая эпоха, состояние из replay,
// полные окна кандидата кормим в обработчик, хвост — в накопитель окна.
func (e *Endpoint) adoptCandidateLocked(c *boundaryCand) {
	e.rxEpoch = c.epoch
	e.rxParams = c.p
	e.rxX = c.x
	e.phaseKnown = true
	e.msSum, e.msN, e.desyncN = 0, 0, 0
	e.desyncGrace = syncWinK * e.symS
	if e.bps == 3 {
		e.desyncGrace = m8VerdictCapWin * e.symS // покрыть скользящий вердикт
	}
	e.highRun = 0
	e.m.Spikes++
	e.pnBits = IdleBitsForEpoch(e.rxM, c.epoch, e.cfg.epochLen()/uint64(e.symS)*uint64(e.bps))
	e.pnEpoch = c.epoch
	e.pnOK = true
	e.pendOn = false
	e.pendCands = nil
	e.pendOld = nil
	// Реплеимые окна уже прошли вердикт захвата; ранняя конвергенция кандидата
	// в них — не показатель здоровья фазы: BER-сторож на них молчит (иначе
	// replay пачкой будит сторож → ложный десинк → перезахват → снова replay —
	// самоподдерживающийся цикл, замерен 2026-09-01: spikes=26 на 1% потерь).
	if e.bps == 3 {
		if n := len(c.resid)/e.symS - m8RegionWin; n > 0 {
			e.gapMute += n
		}
	}
	S := uint64(e.symS)
	e.symAcc = 0
	for k, rk := range c.resid {
		if rk != residAbsent {
			e.symAcc = e.symAcc.Add(rk)
		}
		if (uint64(k) % S) == S-1 {
			if e.bps == 3 {
				e.commitWindowLocked(e.m8.Classify(e.symAcc), uint64(k)/S, c.epoch)
			} else if e.symAcc > 0 {
				e.commitWindowLocked(1, uint64(k)/S, c.epoch)
			} else {
				e.commitWindowLocked(0, uint64(k)/S, c.epoch)
			}
			e.symAcc = 0
		}
	}
	e.rxCount = uint64(len(c.resid))
}

// rxDecodeSymbolLocked — интеграция residual по окну; при завершении окна —
// commitWindowLocked. Вызывается с rxCount = индекс ТЕКУЩЕГО сэмпла эпохи.
// CSK: знак суммы → бит. M8: классификация суммы в уровень → 3 бита.
func (e *Endpoint) rxDecodeSymbolLocked(r Fxp) {
	S := uint64(e.symS)
	symIdx := e.rxCount / S
	e.symAcc = e.symAcc.Add(r)
	if (e.rxCount % S) != S-1 {
		return
	}
	if e.bps == 3 {
		sym := e.m8.Classify(e.symAcc)
		e.symAcc = 0
		e.commitWindowLocked(sym, symIdx, e.rxEpoch)
		return
	}
	bit := e.symAcc > 0
	e.symAcc = 0
	if bit {
		e.commitWindowLocked(1, symIdx, e.rxEpoch)
	} else {
		e.commitWindowLocked(0, symIdx, e.rxEpoch)
	}
}

// commitWindowLocked — завершённое символьное окно; sym — символ окна
// (CSK: 0/1; M8: 0..7). Окна 0..syncWinK-1 — sync-преамбула (сверка с
// ключевым словом, в парсер НЕ идут). Остальные — в парсер кадров (по bps
// бит, старшим первым) + PN-сверка для BER-сторожа.
func (e *Endpoint) commitWindowLocked(sym uint8, symIdx uint64, epoch uint64) {
	bps := uint64(e.bps)
	// Регион sync-слов в начале эпохи parser НЕ кормится вовсе — поэтому кадры
	// переживают границы. CSK: [0,8). M8: [0,m8GuardWin) — транзиент, молчим;
	// [m8GuardWin, m8RegionWin) — чистая вердикт-зона (PN-контроль).
	syncEnd, dataFrom := uint64(syncWinK), uint64(syncWinK)
	if e.bps == 3 {
		syncEnd, dataFrom = uint64(m8GuardWin), uint64(m8RegionWin)
	}
	if symIdx < syncEnd {
		if e.bps == 3 {
			return
		}
		if e.pnOK && (symIdx+1)*bps <= uint64(len(e.pnBits)) {
			e.m.SyncTot += bps
			e.m.SyncBad += uint64(bits.OnesCount8(sym ^ pnWindowSym(e.pnBits, symIdx, e.bps)))
		}
		return
	}
	if symIdx < dataFrom {
		if e.pnOK && (symIdx+1)*bps <= uint64(len(e.pnBits)) {
			e.m.SyncTot += bps
			e.m.SyncBad += uint64(bits.OnesCount8(sym ^ pnWindowSym(e.pnBits, symIdx, e.bps)))
		}
		return
	}
	for k := e.bps - 1; k >= 0; k-- {
		if e.parser.Feed((sym>>uint(k))&1 == 1, epoch) {
			e.berCorrectMarkerLocked(symIdx)
		}
	}
	if e.gapMute > 0 {
		// окно разрыва/восстановления: декод заведомо грязный (потеря уже учтена
		// в InferredLoss) — в BER-метрику и десинк-сторож не идёт
		e.gapMute--
	} else if !e.parser.InFrame() && e.pnOK && (symIdx+1)*bps <= uint64(len(e.pnBits)) {
		bad := uint64(bits.OnesCount8(sym ^ pnWindowSym(e.pnBits, symIdx, e.bps)))
		e.m.BerDen += bps
		e.m.BerNum += bad
		e.berWin += bps
		e.berWinBad += bad
		if e.berWin >= berWatchN {
			if e.berWinBad > berWatchBad {
				// PN не сходится. Если residual живой — уехала фаза, а не
				// поле: ждём следующую границу вместо полного перезахвата.
				e.berWin, e.berWinBad = 0, 0
				if e.lastMs > 0 && e.lastMs < 0.0002 {
					e.phaseKnown = false
				} else {
					e.startHuntLocked(e.lastNow)
					return
				}
			}
			e.berWin, e.berWinBad = 0, 0
		}
	}
	for {
		f := e.parser.Next()
		if f == nil {
			break
		}
		if CheckFrameTag(e.rxM, f.StartEpoch, 0, f.Payload, f.Tag[:]) {
			e.m.FramesOK++
			if len(e.frames) < 32 {
				e.frames = append(e.frames, *f)
			}
		} else {
			e.m.FramesBadTag++
		}
	}
	e.m.FramesBadCRC += uint64(e.parser.badCRC)
	e.parser.badCRC = 0
}

// berCorrectMarkerLocked — ретро-коррекция BER: окна маркера перед curSym
// были посчитаны как PN-ошибки, хотя это биты публичного маркера. Маркер —
// 24 бита = 24/bps окон; текущее окно уже «в кадре» (в PN-BER не посчитано),
// корректируем предыдущие 24/bps−1 окон (CSK: 23, M8: 7).
func (e *Endpoint) berCorrectMarkerLocked(curSym uint64) {
	span := uint64(24/e.bps - 1)
	if curSym < span || !e.pnOK {
		return
	}
	bps := uint64(e.bps)
	var num, den uint64
	for j := uint64(0); j < span; j++ {
		w := curSym - span + j
		for k := uint64(0); k < bps; k++ {
			pb := w*bps + k
			if pb >= uint64(len(e.pnBits)) {
				break
			}
			mbit := (frameMarker>>uint(23-(j*bps+k)))&1 == 1
			den++
			if e.pnBits[pb] != mbit {
				num++
			}
		}
	}
	if e.m.BerDen >= den {
		e.m.BerDen -= den
	}
	if e.m.BerNum >= num {
		e.m.BerNum -= num
	}
}

// fxpToFloat — перевод Q16.48 в float64 ТОЛЬКО для отчётов/метрик.
func fxpToFloat(v Fxp) float64 { return float64(int64(v)) / float64(oneRaw) }

// Snapshot — срез состояния для HTTP-метрик и логов.
type Snapshot struct {
	Mode         string  `json:"mode"`
	Phased       bool    `json:"phased"`
	Epoch        uint64  `json:"epoch"`
	ResidMS      float64 `json:"resid_ms"`
	BER          float64 `json:"ber_est"`
	BerBits      uint64  `json:"ber_bits"`
	JitterAvgMs  float64 `json:"jitter_avg_ms"`
	LossInferred uint64  `json:"loss_inferred"`
	FramesOK     uint64  `json:"frames_ok"`
	FramesBadTag uint64  `json:"frames_bad_tag"`
	FramesBadCRC uint64  `json:"frames_bad_crc"`
	Resyncs      uint64  `json:"resyncs"`
	Spikes       uint64  `json:"spikes"`
	FalseSpikes  uint64  `json:"false_spikes"`
	SyncBad      uint64  `json:"sync_bad"`
	SyncTot      uint64  `json:"sync_tot"`
	TxSamples    uint64  `json:"tx_samples"`
	RxSamples    uint64  `json:"rx_samples"`
}

// Snapshot — текущее состояние (потокобезопасно).
func (e *Endpoint) Snapshot() Snapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := Snapshot{
		Phased:       e.phaseKnown,
		Epoch:        e.rxEpoch,
		ResidMS:      e.lastMs,
		LossInferred: e.m.InferredLoss,
		FramesOK:     e.m.FramesOK,
		FramesBadTag: e.m.FramesBadTag,
		FramesBadCRC: e.m.FramesBadCRC,
		Resyncs:      e.m.Resyncs,
		Spikes:       e.m.Spikes,
		FalseSpikes:  e.m.FalseSpikes,
		SyncBad:      e.m.SyncBad,
		SyncTot:      e.m.SyncTot,
		TxSamples:    e.m.TxSamples,
		RxSamples:    e.m.RxSamples,
		BerBits:      e.m.BerDen,
	}
	if e.mode == rxHunt {
		s.Mode = "hunt"
	} else if e.phaseKnown {
		s.Mode = "phased"
	} else {
		s.Mode = "track"
	}
	if e.m.BerDen > 0 {
		s.BER = float64(e.m.BerNum) / float64(e.m.BerDen)
	}
	if e.jitN > 0 {
		s.JitterAvgMs = e.jitSumMs / float64(e.jitN)
	}
	return s
}

// ChannelQuality — качество канала с точки зрения синхронизации (Э5).
type ChannelQuality struct {
	Synced       bool
	Phased       bool
	LossPermille int
	JitterAvgMs  int
	ResidMS      float64
	BER          float64
}

// Quality — текущее качество канала.
func (e *Endpoint) Quality() ChannelQuality {
	e.mu.Lock()
	defer e.mu.Unlock()
	q := ChannelQuality{Synced: e.mode == rxTrack, Phased: e.phaseKnown, ResidMS: e.lastMs}
	tot := e.m.RxSamples + e.m.InferredLoss
	if tot > 0 {
		q.LossPermille = int(e.m.InferredLoss * 1000 / tot)
	}
	if e.jitN > 0 {
		q.JitterAvgMs = int(e.jitSumMs/float64(e.jitN) + 0.5)
	}
	if e.m.BerDen > 0 {
		q.BER = float64(e.m.BerNum) / float64(e.m.BerDen)
	}
	return q
}

// AutoTune — автопилот в новой роли (Э5): выбор T и c как живой trade-off.
func AutoTune(q ChannelQuality, cfg Config) (Config, []string) {
	rec := cfg.withDefaults()
	var notes []string
	if !q.Synced {
		if rec.Rate > 100 {
			rec.Rate = 100
			notes = append(notes, "нет синхронизма: Rate→100 для устойчивого захвата")
		}
		if rec.SymbolS < 64 {
			rec.SymbolS = 64
			notes = append(notes, "нет синхронизма: S→64 (больше интеграция на символ)")
		}
		if rec.EpochSec < 64 {
			rec.EpochSec = 64
			notes = append(notes, "нет синхронизма: T→64с (реже граничные риски до стабилизации)")
		}
		return rec, notes
	}
	if q.LossPermille > 30 && rec.SymbolS < 128 {
		rec.SymbolS *= 2
		notes = append(notes, "потери >3%: S x2 (интеграция против шума канала)")
	}
	if q.JitterAvgMs*2 > 1000*rec.Batch/rec.Rate && rec.Batch < 8 {
		rec.Batch *= 2
		notes = append(notes, "джиттер велик относительно периода датаграммы: Batch x2")
	}
	if q.ResidMS > 0.001 {
		if rec.Coupling > MustDecimal("0.75") {
			rec.Coupling = MustDecimal("0.75")
			notes = append(notes, "остаточная ошибка велика: c→0.75 (фильтрация шума канала)")
		}
		if rec.EpochSec < 120 {
			rec.EpochSec *= 2
			notes = append(notes, "нестабильный синхронизм: T x2 (реже reseed-риски)")
		}
		return rec, notes
	}
	if q.ResidMS > 0 && q.ResidMS < 0.0001 && q.LossPermille < 10 && q.BER < 0.01 {
		if rec.EpochSec > 8 {
			rec.EpochSec /= 2
			notes = append(notes, "канал чистый и стабильный: T/2 (чаще мутации против реконструкции)")
		}
		if rec.Coupling < MustDecimal("0.95") {
			rec.Coupling = MustDecimal("0.95")
			notes = append(notes, "чистый канал: c→0.95 (быстрая подтяжка после мутаций)")
		}
	}
	return rec, notes
}
