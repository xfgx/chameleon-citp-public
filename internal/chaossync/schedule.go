package chaossync

// schedule.go — ключевое семейство {f_k} и расписание мутаций.
//
// Эпоха m длится T секунд; границы — по счётчику сэмплов, стартовый номер —
// от Unix-времени (обе стороны под NTP, допуск скьюса покрывается захватом
// {m-1, m, m+1}). Параметры поля, топология связей, драйв-сайт и стартовое
// состояние эпохи выводятся из мастер-ключа через проектный DRBG
// (internal/chameleon/drbg.go) по той же схеме, что и расписание Control
// Fabric (cf_schedule.go):
//
//	seed_m = SHA256(master ‖ 0x00 ‖ label ‖ m_be64)
//	params = DRBG(seed_m, ...)
//
// Сторона без мастер-ключа не может предсказать ни f_k, ни форму мутации;
// сторона с ключом вычисляет всё локально, без переговоров по сети.
//
// САМО-ВАЛИДАЦИЯ ПОЛЯ (по итогам измерений 2026-08-30): наивный вывод поля
// давал ~50% эпох с несходящимся наблюдателем (положительный условный
// показатель Ляпунова — измерено: 31 из 60 полей). Поэтому DeriveField после
// вытягивания кандидата прогоняет детерминированную проверку сходимости
// (наблюдатель из чужого состояния, модуляция ключевым PN-потоком эпохи,
// три значения связи из диапазона автопилота). Несходящийся кандидат
// отбрасывается, DRBG продвинут — следующий кандидат другой. Обе стороны
// повторяют это побитово одинаково и получают одно и то же валидное поле
// без какого-либо обмена по сети.
//
// КЛАССЫ ПОЛЕЙ (2026-09-01, по итогам замера Э-A, docs/CHAOS-METRICS.md):
// критерий сходимости наблюдателя требует сильной связи (eps~0.4), которая
// топит хаос — выбранные так прод-поля квазипериодичны (lambda1 ~ +-3e-6,
// h_KS ~ 0). Поэтому назначение поля разделено на два класса со своими
// критериями: FieldClassSync — carrier control-plane (критерий прежний,
// поток кандидатов не изменён — гейт Э1 сохраняется); FieldClassKeystream —
// data-plane keystream и Э6-заявки: хаос-пол, кандидат принимается только при
// lambda1 >= KeystreamLambdaMin (целочисленный Benettin-lite EstimateLambdaMax,
// lambda.go; связь вытягивается из зоны хаоса eps в [0, 0.05)). Отбраковка —
// следующий кандидат из того же DRBG-потока эпохи, побитово одинаково на
// обеих сторонах.

import (
	"crypto/sha256"
	"encoding/binary"
	"math/bits"
	"sync"
	"time"

	"chameleon/internal/chameleon"
)

const (
	schedLabel = "chaossync-field-v2"
	// schedLabelKs — DRBG-метка keystream-класса: независимый от sync поток
	// кандидатов (sync-поток не меняется → исторические поля и гейт Э1 целы).
	schedLabelKs = "chaossync-field-ks-v1"
	cstLabel     = "chaossync-cst-v1"
	idleLabel    = "chaossync-idle-v1"
)

// EpochFor — номер эпохи для момента t при периоде tsec секунд.
func EpochFor(t time.Time, tsec uint64) uint64 {
	if tsec == 0 {
		tsec = 30
	}
	return uint64(t.Unix()) / tsec
}

// epochSeed — SHA256(master ‖ 0x00 ‖ label ‖ epoch_be64).
func epochSeed(master []byte, label string, epoch uint64) []byte {
	var eb [8]byte
	binary.BigEndian.PutUint64(eb[:], epoch)
	h := sha256.New()
	h.Write(master)
	h.Write([]byte{0})
	h.Write([]byte(label))
	h.Write(eb[:])
	return h.Sum(nil)
}

// dirMaster — мастер-ключ направления: c2s и s2c — независимые осцилляторы
// одного ключевого семейства.
func dirMaster(master []byte, dir string) []byte {
	h := sha256.New()
	h.Write(master)
	h.Write([]byte{0})
	h.Write([]byte("chaossync-dir-" + dir))
	return h.Sum(nil)
}

// Пределы вывода параметров (Q16.48-константы, целочисленные диапазоны).
// Диапазоны связи выбраны по измеренному свипу сходимости (2026-08-30):
// ε1 ∈ [0.38, 0.43), ε2 ∈ [0.42, 0.47) — сильная диффузная связь, при ней
// условные показатели Ляпунова отрицательны у подавляющего большинства
// полей (остальные отсекает само-валидация).
var (
	muBase = MustDecimal("3.9")
	muSpan = uint64(28147497671065) // +[0, 0.1)  → μ ∈ [3.9, 4.0)
	e1Base = MustDecimal("0.38")
	e1Span = uint64(14073748835533) // +[0, 0.05) → ε1 ∈ [0.38, 0.43)
	e2Base = MustDecimal("0.42")
	e2Span = uint64(14073748835533) // +[0, 0.05) → ε2 ∈ [0.42, 0.47)
	xBase  = MustDecimal("0.05")
	xSpan  = uint64(253327479039590) // +[0, 0.9)  → x0 ∈ (0.05, 0.95)
)

// ksEpsSpan — диапазон связи keystream-класса: eps1,eps2 ∈ [0, 0.05), зона
// хаоса по свипу Э-A (lambda1 ~ 0.5-0.85 бит/итер; к eps~0.10-0.15 — коллапс
// в порядок). mu и топология вытягиваются той же схемой, что у sync-класса.
const ksEpsSpan = uint64(14073748835533) // +[0, 0.05)

func drawRange(d *chameleon.DRBG, base Fxp, spanRaw uint64) Fxp {
	return base.Add(FromRaw(int64(d.Uint64() % spanRaw)))
}

// drawField — один кандидат sync-класса из текущего состояния DRBG
// (исторические диапазоны связи; поведение не изменялось — гейт Э1).
func drawField(d *chameleon.DRBG) *FieldParams {
	return drawFieldRanged(d, e1Base, e1Span, e2Base, e2Span)
}

// drawFieldRanged — кандидат с заданными диапазонами связи. Порядок
// вытягивания из DRBG идентичен drawField (mu → eps1 → eps2 → топология →
// drive), поэтому sync-класс получает ровно исторический поток кандидатов.
func drawFieldRanged(d *chameleon.DRBG, e1b Fxp, e1s uint64, e2b Fxp, e2s uint64) *FieldParams {
	p := &FieldParams{}
	for i := 0; i < Sites; i++ {
		p.Mu[i] = drawRange(d, muBase, muSpan)
	}
	p.Eps1 = drawRange(d, e1b, e1s)
	p.Eps2 = drawRange(d, e2b, e2s)
	// Топология: случайный гамильтонов цикл (Fisher–Yates поверх DRBG) —
	// мутация меняет структуру связей, а не только скалярные параметры.
	var perm [Sites]int
	for i := range perm {
		perm[i] = i
	}
	for i := Sites - 1; i > 0; i-- {
		j := d.Intn(i + 1)
		perm[i], perm[j] = perm[j], perm[i]
	}
	for pos := 0; pos < Sites; pos++ {
		site := perm[pos]
		p.Next[site] = perm[(pos+1)%Sites]
		p.Prev[site] = perm[(pos+Sites-1)%Sites]
	}
	p.Drive = d.Intn(Sites)
	return p
}

// Константы само-валидации (зонд сходимости).
const (
	probeS           = 32     // сэмплов на окно в зонде
	probeSkipWindows = 4      // окон захвата без учёта (транзиент)
	probeWindows     = 8      // измеренных окон хвоста
	probeWrongOffset = 31337  // сдвиг «чужого» стартового состояния наблюдателя
	probeMaxAttempts = 100000 // аварийный предел перерисовки (недостижим практически)
)

// Параметры хаос-пола keystream-класса. КОНФИГУРИРУЕМЫ, но обязаны быть
// выставлены до первого вывода поля и ОДИНАКОВЫ на обеих сторонах (как весь
// Config): стороны по ним независимо выбирают одно и то же поле эпохи.
var (
	// KeystreamLambdaMin — порог отбора lambda1 (бит/итерация, Q16.48).
	// Стартовая точка 0.5 — по свипу Э-A (хаос при eps<~0.05: 0.5-0.85);
	// финализирована замером приёмки (agent.md, 2026-09-01).
	KeystreamLambdaMin = MustDecimal("0.5")
	// KeystreamLambdaIters — длина Benettin-lite прогона EstimateLambdaMax
	// (8192 итерации ~= 15-25 мс/кандидат на CPU ноды — в бюджете ~50 мс/поле).
	KeystreamLambdaIters = 8192
)

var (
	probeDelta      = Fxp(oneRaw >> 8)       // 2^-8 — дефолтная амплитуда модуляции
	probeMsThresh   = MustDecimal("0.00006") // сходится: ≤~3e-5; не сходится: ≥1e-4
	probeMaxRThresh = MustDecimal("0.025")   // хвостовой пик residual
	probeCouplings  = [3]Fxp{MustDecimal("0.75"), MustDecimal("0.85"), MustDecimal("0.95")}
)

// DeriveField — детерминированный вывод f_k эпохи с само-валидацией
// сходимости. Одинаковый вход → побитово одинаковое ВАЛИДНОЕ поле на обеих
// сторонах.
// fieldCache — кэш выведенных полей по (master, epoch). DeriveField чист и
// детерминирован, но дорог (self-validating зонд сходимости). Без кэша hunt
// КАЖДОГО шумового пира гонял зонд на 3 эпохи -> под фоновым шумом интернета
// (публичный UDP-порт) это истощало пер-тиковый бюджет CPU и реальный пир
// голодал (деградация ноды по аптайму, этап Э5). FieldParams после вывода
// иммутабельны, поэтому из кэша отдаём копию.
const fieldCacheCap = 1024

// FieldClass — класс назначения поля эпохи (2026-09-01, по итогам замера
// Э-A): критерий «сходимость наблюдателя» требует сильной связи, которая
// топит хаос, поэтому keystream/Э6-поля выводятся отдельным классом.
type FieldClass int

const (
	// FieldClassSync — carrier control-plane: критерий без изменений
	// (стабильная связь, сходимость наблюдателя).
	FieldClassSync FieldClass = iota
	// FieldClassKeystream — data-plane keystream/Э6: хаос-пол
	// (lambda1 >= KeystreamLambdaMin, связь из зоны хаоса eps в [0, 0.05)).
	FieldClassKeystream
)

// classLabel — DRBG-метка класса (независимые потоки кандидатов).
func classLabel(class FieldClass) string {
	if class == FieldClassKeystream {
		return schedLabelKs
	}
	return schedLabel
}

type fieldCacheKey struct {
	master [32]byte // sha256(master), сам секрет в ключе не держим
	epoch  uint64
	class  FieldClass
}

var (
	fieldCacheMu sync.Mutex
	fieldCache   = make(map[fieldCacheKey]*FieldParams)
)

// DeriveField — sync-класс (carrier control-plane): исторический критерий
// сходимости наблюдателя, поведение не изменялось — гейт Э1 покрывает этот
// путь (золотой хэш 29f2315f…).
func DeriveField(master []byte, epoch uint64) *FieldParams {
	return DeriveFieldClass(master, epoch, FieldClassSync)
}

// DeriveFieldClass — кэшированная обёртка над deriveFieldUncached.
func DeriveFieldClass(master []byte, epoch uint64, class FieldClass) *FieldParams {
	key := fieldCacheKey{master: sha256.Sum256(master), epoch: epoch, class: class}
	fieldCacheMu.Lock()
	if p, ok := fieldCache[key]; ok {
		fieldCacheMu.Unlock()
		cp := *p
		return &cp
	}
	fieldCacheMu.Unlock()

	p, _ := deriveFieldUncached(master, epoch, class)

	fieldCacheMu.Lock()
	if len(fieldCache) >= fieldCacheCap {
		fieldCache = make(map[fieldCacheKey]*FieldParams)
	}
	fieldCache[key] = p
	fieldCacheMu.Unlock()
	cp := *p
	return &cp
}

// m8ProbeWin — окон поведенческого прогона M8-годности sync-поля.
// Покрывает эпохи длиной до 2048 окон (8192 сэмпла при S=4); более длинные
// эпохи экстраполируют (замечено: тяжёлая враждебность структурна на всё поле,
// лёгкая сидит в первых ~120-340 окнах — обе ловятся прогоном).
const m8ProbeWin = 2048

// m8ProbeMaxBad — максимум ошибочных бит в оцениваемой зоне [m8RegionWin,
// m8ProbeWin) = 5856 бит: ≤2 бита ⇔ bitBER < ~0.05% (замер 2026-09-01 по 128
// эпохам: чистые поля дают 0, лёгкая враждебность ~0.3-0.6%, тяжёлая ~10-50%).
const m8ProbeMaxBad = 2

// fieldM8Suitable — поведенческий зонд годности sync-поля под M8-несущую:
// обе стороны от EpochInit (как replay захвата в сессии), ключевой PN-поток
// эпохи, plain-sum демодуляция при штатных S и c режима M8. Поле годно, если
// ошибок почти нет. Всё целочисленное Q16.48 → бит-идентично Win/Linux.
// Измерение (agent.md 2026-09-01): ~15% sync-полей враждебны M8 (усиление
// отклика гуляет/ломается), и по μ/ε они не отделимы — только поведение.
func fieldM8Suitable(master []byte, epoch uint64, p *FieldParams) bool {
	m8 := NewModem8(Fxp(oneRaw>>8), m8DefaultS)
	c := m8DefaultCoupling
	tx := EpochInit(master, epoch)
	rx := EpochInit(master, epoch)
	pn := pnSymbolsForEpoch(master, epoch, m8ProbeWin, 3)
	bad := 0
	for w := 0; w < m8ProbeWin; w++ {
		sym := pn[w]
		var acc Fxp
		for s := 0; s < m8DefaultS; s++ {
			p.Step(&tx)
			m8.Perturb(&tx, p.Drive, sym)
			y := Quantize16(tx[p.Drive])
			r := p.ObserverStep(&rx, Dequantize16(y), c)
			acc = acc.Add(r)
		}
		if w >= m8RegionWin {
			bad += bits.OnesCount8(m8.Classify(acc) ^ sym)
			if bad > m8ProbeMaxBad {
				return false
			}
		}
	}
	return true
}

// deriveFieldUncached — вывод поля класса; возвращает поле и число
// кандидатов (1 + отбраковано) для телеметрии/тестов.
func deriveFieldUncached(master []byte, epoch uint64, class FieldClass) (*FieldParams, int) {
	d := chameleon.NewDRBG(epochSeed(master, classLabel(class), epoch), "params")
	for attempt := 0; attempt < probeMaxAttempts; attempt++ {
		if class == FieldClassKeystream {
			// Хаос-пол: кандидат из зоны хаоса (eps в [0, 0.05)) принимается
			// только при lambda1 >= KeystreamLambdaMin. Отбраковка — следующий
			// кандидат из того же DRBG-потока эпохи (детерминировано на обеих
			// сторонах). Оценка lambda1 целочисленная → бит-идентична Win/Linux.
			p := drawFieldRanged(d, Fxp(0), ksEpsSpan, Fxp(0), ksEpsSpan)
			if EstimateLambdaMax(p, KeystreamLambdaIters) >= KeystreamLambdaMin {
				return p, attempt + 1
			}
			continue
		}
		p := drawField(d)
		if fieldConverges(master, epoch, p) && fieldM8Suitable(master, epoch, p) {
			// sync-класс: сходимость наблюдателя (как было, инвариант CSK) +
			// M8-годность несущей (отбраковка — следующий из того же DRBG,
			// детерминировано на обеих сторонах; Э1-поле измерено чистым —
			// золотой хэш гейта Э1 этот зонд не сдвигает).
			return p, attempt + 1
		}
	}
	// Недостижимо статистически; обе стороны упали бы одинаково — fail-closed
	// сохраняется даже здесь.
	panic("chaossync: поле не прошло отбор класса после probeMaxAttempts перерисовок")
}

// DeriveDrives — выбор k различных драйв-сайтов для многомерного кодирования.
// Сайты равномерно разнесены по гамильтонову циклу связи (минимум перекрёстного
// влияния). Детерминировано из уже выведенной топологии поля, DRBG НЕ расходует
// -> одноканальный путь и золотой хэш Э1 не меняются. При k=1 возвращает
// [base.Drive] (тождественно доказанному одноканальному пути).
func DeriveDrives(base *FieldParams, k int) []int {
	if k < 1 {
		k = 1
	}
	if k > Sites {
		k = Sites
	}
	// порядок обхода цикла связи, начиная с базового драйв-сайта
	order := make([]int, 0, Sites)
	cur := base.Drive
	for len(order) < Sites {
		order = append(order, cur)
		cur = base.Next[cur]
	}
	// k равномерно разнесённых по циклу позиций
	drives := make([]int, 0, k)
	for i := 0; i < k; i++ {
		drives = append(drives, order[(i*Sites)/k])
	}
	return drives
}

// fieldConverges — детерминированная проверка: наблюдатель из чужого
// состояния обязан сойтись при всех рабочих значениях связи автопилота.
// Вычисления целочисленные и идентичны на обеих сторонах.
func fieldConverges(master []byte, epoch uint64, p *FieldParams) bool {
	pn := IdleBitsForEpoch(master, epoch, probeSkipWindows+probeWindows)
	for _, c := range probeCouplings {
		if !convergesAt(master, epoch, p, pn, c) {
			return false
		}
	}
	return true
}

// convergesAt — зонд сходимости при одном значении связи: TX идёт из
// EpochInit эпохи с модуляцией PN-потоком, наблюдатель — из чужого состояния.
// Меряем хвостовые ms и max|r|. Сходится ⇔ оба под порогом.
func convergesAt(master []byte, epoch uint64, p *FieldParams, pn []bool, c Fxp) bool {
	txX := EpochInit(master, epoch)
	rxX := EpochInit(master, epoch+probeWrongOffset)
	mod := Modulator{Delta: probeDelta, S: probeS}
	var maxR, sumSq Fxp
	n := 0
	total := (probeSkipWindows + probeWindows) * probeS
	for i := 0; i < total; i++ {
		bit := pn[i/probeS]
		p.Step(&txX)
		mod.Perturb(&txX, p.Drive, bit)
		y := Quantize16(txX[p.Drive])
		r := p.ObserverStep(&rxX, Dequantize16(y), c)
		if i >= probeSkipWindows*probeS {
			if r.Abs() > maxR {
				maxR = r.Abs()
			}
			sumSq = sumSq.Add(r.Mul(r))
			n++
		}
	}
	ms := Fxp(int64(sumSq) / int64(n))
	return ms <= probeMsThresh && maxR <= probeMaxRThresh
}

// EpochInit — ключевой reseed состояния на границе эпохи (sync-класс).
// Поведение не изменялось — гейт Э1. Обе стороны перепрыгивают в одну и ту же
// точку нового аттрактора.
func EpochInit(master []byte, epoch uint64) [Sites]Fxp {
	return EpochInitClass(master, epoch, FieldClassSync)
}

// EpochInitClass — reseed состояния эпохи для класса поля: поток
// инициализации выводится из метки класса (у keystream-полей — своё
// стартовое состояние, независимое от sync).
func EpochInitClass(master []byte, epoch uint64, class FieldClass) [Sites]Fxp {
	d := chameleon.NewDRBG(epochSeed(master, classLabel(class), epoch), "init")
	var x [Sites]Fxp
	for i := 0; i < Sites; i++ {
		x[i] = drawRange(d, xBase, xSpan)
	}
	return x
}

// IdleBit — бит холостого PN-потока эпохи для символа symIdx. Известен обеим
// сторонам: приёмник оценивает BER непрерывно, не прерывая передачу.
// Дорого (сдвиг DRBG за раз) — для массового доступа используйте
// IdleBitsForEpoch.
func IdleBit(master []byte, epoch uint64, symIdx uint64) bool {
	d := chameleon.NewDRBG(epochSeed(master, idleLabel, epoch), "idle")
	blk := symIdx >> 3
	var b byte
	for i := uint64(0); i <= blk; i++ {
		b = d.Bytes(1)[0]
	}
	return (b>>(uint(symIdx)&7))&1 == 1
}

// IdleBitsForEpoch — весь PN-поток эпохи разом (по одному биту на символьное
// окно). Разложение битов совпадает с IdleBit: бит i — это (байт i/8) >>
// (i%8) & 1 потока DRBG(сид_эпохи, "idle").
func IdleBitsForEpoch(master []byte, epoch uint64, nWindows uint64) []bool {
	d := chameleon.NewDRBG(epochSeed(master, idleLabel, epoch), "idle")
	raw := d.Bytes(int((nWindows + 7) / 8))
	bits := make([]bool, nWindows)
	for i := range bits {
		bits[i] = (raw[i/8]>>uint(i%8))&1 == 1
	}
	return bits
}

// pnWindowSym — ожидаемый PN-символ окна w из битового PN-потока: биты окна
// [bps·w, bps·w+bps), первый бит — старший. Одинаково на обеих сторонах.
func pnWindowSym(pn []bool, w uint64, bps int) uint8 {
	var v uint8
	for k := 0; k < bps; k++ {
		v <<= 1
		if pn[w*uint64(bps)+uint64(k)] {
			v |= 1
		}
	}
	return v
}

// pnSymbolsForEpoch — PN-поток эпохи, упакованный в M-арные символы окон
// (M8: bps=3). Используется TX для sync-преамбулы и холостого потока
// (ленивый IdleBit при S~1-2 сэмпла на окно был бы квадратично дорогим).
func pnSymbolsForEpoch(master []byte, epoch uint64, nWin uint64, bps int) []uint8 {
	bits := IdleBitsForEpoch(master, epoch, nWin*uint64(bps))
	out := make([]uint8, nWin)
	for w := range out {
		out[w] = pnWindowSym(bits, uint64(w), bps)
	}
	return out
}

// SidForEpoch — CST-значение эпохи (continuity session ticket): носитель
// непрерывности идентичности поверх мутирующего поля.
func SidForEpoch(master []byte, epoch uint64) []byte {
	return epochSeed(master, cstLabel, epoch)
}
