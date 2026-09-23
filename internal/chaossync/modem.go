package chaossync

// modem.go — модуляция/демодуляция и кадрирование битового уровня.
//
// Модуляция (chaos shift keying в динамике): бит b в течение окна из S
// сэмплов смещает драйв-сайт на +δ (b=1) или −δ (b=0) после шага свободной
// динамики, до квантования. Декод: приёмник интегрирует ошибку
// синхронизации r за окно; знак суммы → бит. Окна выровнены по счётчику
// сэмплов эпохи, который обе стороны ведут одинаково (session.go).
//
// Кадр битового уровня (существует ТОЛЬКО в модуляционном домене — в
// UDP-датаграмме нет ни одного служебного бита):
//
//	marker 24 бита | len×3 24 бита | (payload ‖ tag ‖ crc)×3 блочно-перемежённо
//
// FEC — репитиция ×3 с блочным перемежением и мажоритарным голосованием.
// Причина (измерено 2026-08-30): сырой канал даёт ~0 ошибок в середине эпохи
// и редкие всплески (1-2 бита) у границ эпох на переходных процессах
// принятия. Блочное перемежение разносит три копии бита на ~весь кадр, поэтому
// локальный всплеск длиной в десятки окон портит не более одной копии бита.
// Сырой BER и пост-FEC надёжность кадров измеряются раздельно и честно.
//
// Холостой поток — ключевой PN (IdleBit/IdleBitsForEpoch, schedule.go):
// приёмник непрерывно оценивает BER по известной последовательности.

import (
	"errors"
	"math/bits"
)

const (
	// frameMarker — 24-битное уникальное слово кадра (константа золотого
	// сечения: приличная автокорреляция, нулевая секретность — маркер
	// публичен, аутентификацию даёт cst-tag).
	frameMarker = uint32(0x9E3779)
	tagBits     = 16 // cst-tag
	crcBits     = 16 // crc16
	maxPayload  = 200
)

// ErrPayloadTooLarge — кадр больше допустимого (control-plane профиль).
var ErrPayloadTooLarge = errors.New("chaossync: payload > 200 bytes")

// ErrPayloadEmpty — пустой кадр не передаётся.
var ErrPayloadEmpty = errors.New("chaossync: empty payload")

// Modulator — параметры модуляции (δ, S). Одинаковы на обеих сторонах.
type Modulator struct {
	Delta Fxp
	S     int
}

// Perturb — смещение драйв-сайта на ±δ с насыщением в [0, 1). Применять
// ПОСЛЕ FieldParams.Step, ДО Quantize16.
func (m Modulator) Perturb(x *[Sites]Fxp, drive int, bit bool) {
	d := m.Delta
	if !bit {
		d = -d
	}
	v := x[drive].Add(d)
	if v < 0 {
		v = 0
	}
	if v >= One {
		v = Fxp(oneRaw - 1)
	}
	x[drive] = v
}

// --- M=8 модуляция синхро-многообразия (2026-09-01, по числам Э-B) -----------

// Modulation — физический слой символа carrier'а. ОБЯЗАН совпадать на обеих
// сторонах (как весь Config): совпадение — часть скрытой аутентификации.
type Modulation int

const (
	// ModulationM8 — 8-уровневая модуляция (3 бита на символьное окно): дефолт
	// carrier'а по итогам замера Э-B (колено ~2.5 бит/сэмпл vs 0.031 у CSK —
	// до ×83 на том же проводе, docs/CHAOS-METRICS.md).
	ModulationM8 Modulation = iota
	// ModulationCSK — исторический бинарный CSK (±δ, 1 бит/окно): fallback на
	// случай деградации канала (фиче-флаг, логическая сессия/CST сохраняется).
	ModulationCSK
)

// m8DefaultS — дефолт сэмплов на символ M8. Финализирован замером
// (TestM8ClassifySweep, прод-поле, реальный провод, c=0.95): S=4 → 0 ошибок
// на 30000 окон (bit BER < 3e-6 против предела rep3-запаса 2e-3); S=3 →
// 5.6e-5 тоже годится, S=4 взят за запас против экскурсий усиления
// наблюдателя (мультипликативный шум, см. agent.md 2026-09-01). Линейная
// ёмкость 3/4 бит/сэмпл × rate → гейт 1.5 кбит/с/плечо при rate ≥ ~2030.
const m8DefaultS = 4

// gray3 — 3-битный Грей: биты символа потока v → индекс уровня созвездия.
// Соседние уровни различаются ровно одним битом: доминирующая ошибка
// классификатора (промах на соседний уровень, см. Э-B) стоит 1 бит из 3.
func gray3(v uint8) uint8 { return v ^ (v >> 1) }

// gray3Inv — обратное отображение: индекс уровня → биты символа потока.
func gray3Inv(g uint8) uint8 { return g ^ (g >> 1) ^ (g >> 2) }

// Modem8 — M=8 модем: 8-уровневое созвездие сдвигов драйв-сайта.
//
// Уровни: levels[ℓ] = Delta·(2ℓ−7)/7, ℓ ∈ {0..7} — равномерно по достижимому
// диапазону синхро-многообразия ±Delta (НЕ по амплитуде вслепую): Delta =
// 2^-8 — бюджет, на котором Э-B измерил колено ~2.5 бит/сэмпл; пик равен
// боевому δ CSK → транзиенты модуляции не растут, пороговая логика границ
// эпох (spikeThresh/highRunThresh) не затрагивается. Деление на 7 —
// целочисленное, один раз при инициализации → побитово одинаково везде.
//
// Демодулятор — plain-sum интегратор residual по окну (как у CSK, но в 8
// уровней по серединным порогам ×S). По замерам 2026-09-01 (m8-раунды 1-5,
// agent.md): доминирующий шум классификатора — мультипликативные экскурсии
// усиления наблюдателя от хвоста (1−c)·r; они подавляются связью c=0.95
// (дефолт режима M8, m8DefaultCoupling). Guard-интервал (skip первого сэмпла)
// и receiver-side whitening измерены и ОПРОВЕРГНУТЫ как дефолт: guard хуже на
// всех S (первый сэмпл несёт основной сигнал), whitening при c=0.85 помогает
// (0.88%→0.41% бит), но c=0.95+plain чище (≈0) и проще.
type Modem8 struct {
	S      int    // сэмплов на символьное окно
	Levels [8]Fxp // сдвиг драйв-сайта по индексу уровня (Грей от битов потока)
	thr    [7]Fxp // серединные пороги классификатора, заранее ×S (для Σr окна)
}

// Sync-регион M8 в начале эпохи (по картам транзиента 2026-09-01, 64 эпохи):
// после рестарта из EpochInit первые ~30-55 окон несут враждебный gain
// (внеаттракторный транзиент + экскурсии усиления наблюдателя), а «пол»
// ~3-6% эпох не исчезает и дальше — строгий вердикт 8/8 первых окон для M8
// нежизнеспособен (CSK переживает его запасом знака суммы и не меняется).
// Поэтому для M8: окна [0, m8GuardWin) — молчаливый ключевой PN (ни parser,
// ни BER-сторож туда не смотрят), окна [m8GuardWin, m8RegionWin) —
// вердикт-зона захвата фазы (кворум m8VerdictQuorum из m8VerdictWin) и
// PN-контроль SyncTot/SyncBad; данные — с окна m8RegionWin. Замер вердикта:
// истинная граница 62/64 (сбойные эпохи до-захватываются на следующей),
// чужое поле 0/64, off-by-one 0/64 (его убивает pre-filter: max|r| ≥ 0.15).
const (
	m8GuardWin      = 64
	m8VerdictWin    = 32
	m8RegionWin     = m8GuardWin + m8VerdictWin // 96 — конец sync-региона (данные с этого окна)
	m8VerdictQuorum = 24                        // совпадений из m8VerdictWin окон (75%)
	m8VerdictMinOK  = 26                        // из них — минимум окон без разрывов канала
	m8VerdictCapWin = 192                       // скользящий предел зоны вердикта
)

// m8DefaultCoupling — дефолт связи наблюдателя в режиме M8 (переопределяется
// явным Config.Coupling). По замеру 2026-09-01: при c=0.95 plain-sum BER ≈ 0
// на прод-поле уже при S=3-4; при историческом 0.85 — 0.4-0.9% бит (rep3 на
// пределе). Поля сертифицированы пробой сходимости на c ∈ {0.75, 0.85, 0.95}.
var m8DefaultCoupling = MustDecimal("0.95")

// NewModem8 — созвездие и пороги для (δ, S).
func NewModem8(delta Fxp, s int) Modem8 {
	if s < 1 {
		s = 1
	}
	m := Modem8{S: s}
	for l := 0; l < 8; l++ {
		m.Levels[l] = Fxp(int64(delta) * int64(2*l-7) / 7)
	}
	for j := 0; j < 7; j++ {
		mid := Fxp(int64(m.Levels[j].Add(m.Levels[j+1])) >> 1)
		m.thr[j] = mid.Mul(FromInt(int64(s)))
	}
	return m
}

// Perturb — смещение драйв-сайта на сдвиг уровня символа v (0..7, биты
// потока) с насыщением в [0, 1). Применять ПОСЛЕ FieldParams.Step, ДО
// Quantize16.
func (m Modem8) Perturb(x *[Sites]Fxp, drive int, v uint8) {
	d := m.Levels[gray3(v&7)]
	val := x[drive].Add(d)
	if val < 0 {
		val = 0
	}
	if val >= One {
		val = Fxp(oneRaw - 1)
	}
	x[drive] = val
}

// Classify — ML-решение по интегралу residual за окно: ближайший уровень по
// серединным порогам (равномерные априоры, одинаковый шум уровней — Э-B).
// Возвращает биты символа потока (0..7). Целочисленные сравнения →
// детерминировано на всех платформах.
func (m Modem8) Classify(acc Fxp) uint8 {
	l := uint8(0)
	for l < 7 && acc >= m.thr[l] {
		l++
	}
	return gray3Inv(l)
}

// crc16CCITT — CRC-16-CCITT (poly 0x1021, init 0xFFFF), побитово.
func crc16CCITT(data []byte) uint16 {
	crc := uint16(0xFFFF)
	for _, b := range data {
		crc ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// appendBits дописывает value длиной n бит (MSB first) в поток.
func appendBits(dst []bool, value uint64, n int) []bool {
	for i := n - 1; i >= 0; i-- {
		dst = append(dst, (value>>uint(i))&1 == 1)
	}
	return dst
}

// appendRep3 дописывает блок bits трижды с блочным перемежением:
// позиция копии c бита i = c*len + i. Всплеск длиной < len бьёт не более
// одной копии любого бита.
func appendRep3(dst []bool, bits []bool) []bool {
	for c := 0; c < 3; c++ {
		dst = append(dst, bits...)
	}
	return dst
}

// rep3Decode — мажоритарное голосование по трём перемежённым копиям.
func rep3Decode(stream []bool) []bool {
	if len(stream)%3 != 0 {
		return nil
	}
	n := len(stream) / 3
	out := make([]bool, n)
	for i := 0; i < n; i++ {
		votes := 0
		if stream[i] {
			votes++
		}
		if stream[i+n] {
			votes++
		}
		if stream[i+2*n] {
			votes++
		}
		out[i] = votes >= 2
	}
	return out
}

// frameEncoder — очередь кадров → битовый поток; между кадрами — PN idle.
type frameEncoder struct {
	queue [][]byte
	bits  []bool // активный кадр побитово
	pos   int
}

func newFrameEncoder() *frameEncoder { return &frameEncoder{} }

// Push ставит кадр в очередь (1..200 байт).
func (e *frameEncoder) Push(payload []byte) error {
	if len(payload) == 0 {
		return ErrPayloadEmpty
	}
	if len(payload) > maxPayload {
		return ErrPayloadTooLarge
	}
	cp := make([]byte, len(payload))
	copy(cp, payload)
	e.queue = append(e.queue, cp)
	return nil
}

// buildFrame собирает битовый массив кадра: marker | rep3(len) | rep3(body).
// body = payload ‖ cst-tag ‖ crc16(len‖payload). tag = FrameTag(txDirMaster,
// epoch, 0, payload) — epoch старта кадра.
func buildFrame(txM []byte, epoch uint64, payload []byte) []bool {
	var bits []bool
	bits = appendBits(bits, uint64(frameMarker), 24)
	// len (8 бит) ×3 перемежено
	var lenBits []bool
	lenBits = appendBits(lenBits, uint64(len(payload)), 8)
	bits = appendRep3(bits, lenBits)
	// body = payload ‖ tag ‖ crc
	var body []bool
	for _, b := range payload {
		body = appendBits(body, uint64(b), 8)
	}
	tag := FrameTag(txM, epoch, 0, payload)
	body = appendBits(body, uint64(tag[0]), 8)
	body = appendBits(body, uint64(tag[1]), 8)
	lb := append([]byte{byte(len(payload))}, payload...)
	body = appendBits(body, uint64(crc16CCITT(lb)), 16)
	bits = appendRep3(bits, body)
	return bits
}

// nextBit — следующий бит потока: активный кадр, иначе новый из очереди,
// иначе ключевой PN idle. symIdx — индекс символьного окна внутри эпохи.
func (e *frameEncoder) nextBit(txM []byte, epoch, symIdx uint64) bool {
	if e.pos < len(e.bits) {
		b := e.bits[e.pos]
		e.pos++
		return b
	}
	if len(e.queue) > 0 {
		payload := e.queue[0]
		e.queue = e.queue[1:]
		e.bits = buildFrame(txM, epoch, payload)
		e.pos = 1
		return e.bits[0]
	}
	return IdleBit(txM, epoch, symIdx)
}

// nextSymM8 — следующий 3-битный символ потока (M8): активный кадр, иначе
// новый из очереди, иначе ключевой PN idle (кэш эпохи, см. txIdle). Длина
// кадра в битах всегда кратна 3 (marker 24 ‖ rep3(len) 24 ‖ rep3(body)
// 3·(8L+32)), поэтому кадр не обрывается посередине символа; первый бит
// потока — старший бит символа.
func (e *frameEncoder) nextSymM8(txM []byte, epoch, symIdx uint64, pn []uint8) uint8 {
	if e.pos+3 > len(e.bits) && len(e.queue) > 0 {
		payload := e.queue[0]
		e.queue = e.queue[1:]
		e.bits = buildFrame(txM, epoch, payload)
		e.pos = 0
	}
	if e.pos+3 <= len(e.bits) {
		v := uint8(0)
		for k := 0; k < 3; k++ {
			v <<= 1
			if e.bits[e.pos+k] {
				v |= 1
			}
		}
		e.pos += 3
		return v
	}
	return pn[symIdx]
}

// ParsedFrame — собранный кадр: полезная часть и сырой cst-tag.
type ParsedFrame struct {
	Payload    []byte
	Tag        [FrameTagLen]byte
	StartEpoch uint64
}

// frameParser — поточечный поиск marker и сборка кадра с rep3-декодом.
// Состояния: HUNT (поиск маркера) → LEN (24 бита) → BODY (3·(8L+32) бита).
type frameParser struct {
	shift        uint32
	nbits        int
	stage        int // 0=HUNT, 1=LEN, 2=BODY
	bits         []bool
	need         int
	startEpoch   uint64
	epochRing    [24]uint64
	epochPos     int
	ready        []ParsedFrame
	badCRC       int // кадры, убитые CRC (метрика)
	markersFound int // найдено маркеров (диагностика)
	badLen       int // кадры, убитые мажоритарно-битой длиной (метрика)
}

func newFrameParser() *frameParser { return &frameParser{} }

// Reset сбрасывает состояние парсера (перезахват поля, разрыв потока).
func (p *frameParser) Reset() {
	p.shift = 0
	p.nbits = 0
	p.stage = 0
	p.bits = p.bits[:0]
	p.need = 0
	p.ready = nil
}

// InFrame — true, если парсер сейчас собирает кадр (BER по PN не считаем).
func (p *frameParser) InFrame() bool { return p.stage != 0 }

// Feed подаёт один декодированный бит; epoch — эпоха этого символьного окна.
// Возвращает true, если на этом бите завершилось обнаружение маркера.
func (p *frameParser) Feed(bit bool, epoch uint64) bool {
	if p.stage == 0 {
		p.shift = (p.shift << 1) & 0xFFFFFF
		if bit {
			p.shift |= 1
		}
		p.nbits++
		p.epochRing[p.epochPos] = epoch
		p.epochPos = (p.epochPos + 1) % 24
		if p.nbits >= 24 && bits.OnesCount32(p.shift^frameMarker) <= 2 {
			p.markersFound++
			p.stage = 1
			p.bits = p.bits[:0]
			p.need = 0
			p.startEpoch = p.epochRing[p.epochPos]
			return true
		}
		return false
	}
	p.bits = append(p.bits, bit)
	if p.stage == 1 && len(p.bits) == 24 {
		lb := rep3Decode(p.bits)
		l := bitsToByte(lb)
		if l == 0 || int(l) > maxPayload {
			p.badLen++
			p.Reset()
			return false
		}
		p.need = 3 * (int(l)*8 + tagBits + crcBits)
		p.stage = 2
		p.bits = p.bits[:0]
		return false
	}
	if p.stage == 2 && len(p.bits) == p.need {
		body := rep3Decode(p.bits)
		l := (len(body) - tagBits - crcBits) / 8
		payload := make([]byte, l)
		for i := 0; i < l; i++ {
			payload[i] = bitsToByte(body[i*8 : (i+1)*8])
		}
		off := l * 8
		var fr ParsedFrame
		fr.Tag[0] = bitsToByte(body[off : off+8])
		fr.Tag[1] = bitsToByte(body[off+8 : off+16])
		crc := uint16(0)
		for i := 0; i < 16; i++ {
			crc <<= 1
			if body[off+16+i] {
				crc |= 1
			}
		}
		lb := append([]byte{byte(l)}, payload...)
		if crc16CCITT(lb) == crc {
			fr.Payload = payload
			fr.StartEpoch = p.startEpoch
			p.ready = append(p.ready, fr)
		} else {
			p.badCRC++
		}
		p.stage = 0
		p.nbits = 0
		p.shift = 0
		return false
	}
	return false
}

// Next извлекает следующий собранный кадр (nil, если нет).
func (p *frameParser) Next() *ParsedFrame {
	if len(p.ready) == 0 {
		return nil
	}
	f := p.ready[0]
	p.ready = p.ready[1:]
	return &f
}

func bitsToByte(bits []bool) byte {
	var b byte
	for _, bit := range bits {
		b <<= 1
		if bit {
			b |= 1
		}
	}
	return b
}
