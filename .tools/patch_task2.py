#!/usr/bin/env python3
# patch_task2.py — Задача 2: M=8 модуляция в chaossync carrier (modem/schedule/session).
import sys
ROOT = "/files/VPN"

def patch(path, edits, append=None):
    p = ROOT + "/" + path
    src = open(p, encoding="utf-8").read()
    for name, old, new, cnt in edits:
        n = src.count(old)
        if n != cnt:
            print(f"FAIL {path} [{name}]: anchor found {n}, want {cnt}", file=sys.stderr)
            sys.exit(1)
        src = src.replace(old, new)
        print(f"  ok {path} [{name}]")
    if append:
        if append.strip() in src:
            print(f"  skip {path} [append present]")
        else:
            if not src.endswith("\n"):
                src += "\n"
            src += append
            print(f"  ok {path} [append]")
    open(p, "w", encoding="utf-8").write(src)

# ================= modem.go =================
modem = []

# M8-блок после Modulator.Perturb
modem.append(("m8-block", """// Perturb — смещение драйв-сайта на ±δ с насыщением в [0, 1). Применять
// ПОСЛЕ FieldParams.Step, ДО Quantize16.
func (m Modulator) Perturb(x *[Sites]Fxp, drive int, bit bool) {
\td := m.Delta
\tif !bit {
\t\td = -d
\t}
\tv := x[drive].Add(d)
\tif v < 0 {
\t\tv = 0
\t}
\tif v >= One {
\t\tv = Fxp(oneRaw - 1)
\t}
\tx[drive] = v
}
""",
"""// Perturb — смещение драйв-сайта на ±δ с насыщением в [0, 1). Применять
// ПОСЛЕ FieldParams.Step, ДО Quantize16.
func (m Modulator) Perturb(x *[Sites]Fxp, drive int, bit bool) {
\td := m.Delta
\tif !bit {
\t\td = -d
\t}
\tv := x[drive].Add(d)
\tif v < 0 {
\t\tv = 0
\t}
\tif v >= One {
\t\tv = Fxp(oneRaw - 1)
\t}
\tx[drive] = v
}

// --- M=8 модуляция синхро-многообразия (2026-09-01, по числам Э-B) -----------

// Modulation — физический слой символа carrier'а. ОБЯЗАН совпадать на обеих
// сторонах (как весь Config): совпадение — часть скрытой аутентификации.
type Modulation int

const (
\t// ModulationM8 — 8-уровневая модуляция (3 бита на символьное окно): дефолт
\t// carrier'а по итогам замера Э-B (колено ~2.5 бит/сэмпл vs 0.031 у CSK —
\t// до ×83 на том же проводе, docs/CHAOS-METRICS.md).
\tModulationM8 Modulation = iota
\t// ModulationCSK — исторический бинарный CSK (±δ, 1 бит/окно): fallback на
\t// случай деградации канала (фиче-флаг, логическая сессия/CST сохраняется).
\tModulationCSK
)

// m8DefaultS — сэмплов на символ в режиме M8 по умолчанию. Финализировано
// замером символьного BER против запаса rep3-FEC на канале с потерями 1% и
// джиттером (m8_test.go; числа — в agent.md 2026-09-01).
const m8DefaultS = 2

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
type Modem8 struct {
\tS      int    // сэмплов на символьное окно
\tLevels [8]Fxp // сдвиг драйв-сайта по индексу уровня (Грей от битов потока)
\tthr    [7]Fxp // серединные пороги классификатора, заранее ×S (для Σr окна)
}

// NewModem8 — созвездие и пороги для (δ, S).
func NewModem8(delta Fxp, s int) Modem8 {
\tif s < 1 {
\t\ts = 1
\t}
\tm := Modem8{S: s}
\tfor l := 0; l < 8; l++ {
\t\tm.Levels[l] = Fxp(int64(delta) * int64(2*l-7) / 7)
\t}
\tfor j := 0; j < 7; j++ {
\t\tmid := Fxp(int64(m.Levels[j].Add(m.Levels[j+1])) >> 1)
\t\tm.thr[j] = mid.Mul(FromInt(int64(s)))
\t}
\treturn m
}

// Perturb — смещение драйв-сайта на сдвиг уровня символа v (0..7, биты
// потока) с насыщением в [0, 1). Применять ПОСЛЕ FieldParams.Step, ДО
// Quantize16.
func (m Modem8) Perturb(x *[Sites]Fxp, drive int, v uint8) {
\td := m.Levels[gray3(v&7)]
\tval := x[drive].Add(d)
\tif val < 0 {
\t\tval = 0
\t}
\tif val >= One {
\t\tval = Fxp(oneRaw - 1)
\t}
\tx[drive] = val
}

// Classify — ML-решение по интегралу residual за окно: ближайший уровень по
// серединным порогам (равномерные априоры, одинаковый шум уровней — Э-B).
// Возвращает биты символа потока (0..7). Целочисленные сравнения →
// детерминировано на всех платформах.
func (m Modem8) Classify(acc Fxp) uint8 {
\tl := uint8(0)
\tfor l < 7 && acc >= m.thr[l] {
\t\tl++
\t}
\treturn gray3Inv(l)
}
""", 1))

# nextSymM8 после nextBit
modem.append(("nextsym", """\treturn IdleBit(txM, epoch, symIdx)
}
""",
"""\treturn IdleBit(txM, epoch, symIdx)
}

// nextSymM8 — следующий 3-битный символ потока (M8): активный кадр, иначе
// новый из очереди, иначе ключевой PN idle (кэш эпохи, см. txIdle). Длина
// кадра в битах всегда кратна 3 (marker 24 ‖ rep3(len) 24 ‖ rep3(body)
// 3·(8L+32)), поэтому кадр не обрывается посередине символа; первый бит
// потока — старший бит символа.
func (e *frameEncoder) nextSymM8(txM []byte, epoch, symIdx uint64, pn []uint8) uint8 {
\tif e.pos+3 > len(e.bits) && len(e.queue) > 0 {
\t\tpayload := e.queue[0]
\t\te.queue = e.queue[1:]
\t\te.bits = buildFrame(txM, epoch, payload)
\t\te.pos = 0
\t}
\tif e.pos+3 <= len(e.bits) {
\t\tv := uint8(0)
\t\tfor k := 0; k < 3; k++ {
\t\t\tv <<= 1
\t\t\tif e.bits[e.pos+k] {
\t\t\t\tv |= 1
\t\t\t}
\t\t}
\t\te.pos += 3
\t\treturn v
\t}
\treturn pn[symIdx]
}
""", 1))

patch("internal/chaossync/modem.go", modem)

# ================= schedule.go =================
sch = []
sch.append(("pn-symbols", """// IdleBitsForEpoch — весь PN-поток эпохи разом (по одному биту на символьное
// окно). Разложение битов совпадает с IdleBit: бит i — это (байт i/8) >>
// (i%8) & 1 потока DRBG(сид_эпохи, "idle").
func IdleBitsForEpoch(master []byte, epoch uint64, nWindows uint64) []bool {
\td := chameleon.NewDRBG(epochSeed(master, idleLabel, epoch), "idle")
\traw := d.Bytes(int((nWindows + 7) / 8))
\tbits := make([]bool, nWindows)
\tfor i := range bits {
\t\tbits[i] = (raw[i/8]>>uint(i%8))&1 == 1
\t}
\treturn bits
}
""",
"""// IdleBitsForEpoch — весь PN-поток эпохи разом (по одному биту на символьное
// окно). Разложение битов совпадает с IdleBit: бит i — это (байт i/8) >>
// (i%8) & 1 потока DRBG(сид_эпохи, "idle").
func IdleBitsForEpoch(master []byte, epoch uint64, nWindows uint64) []bool {
\td := chameleon.NewDRBG(epochSeed(master, idleLabel, epoch), "idle")
\traw := d.Bytes(int((nWindows + 7) / 8))
\tbits := make([]bool, nWindows)
\tfor i := range bits {
\t\tbits[i] = (raw[i/8]>>uint(i%8))&1 == 1
\t}
\treturn bits
}

// pnWindowSym — ожидаемый PN-символ окна w из битового PN-потока: биты окна
// [bps·w, bps·w+bps), первый бит — старший. Одинаково на обеих сторонах.
func pnWindowSym(pn []bool, w uint64, bps int) uint8 {
\tvar v uint8
\tfor k := 0; k < bps; k++ {
\t\tv <<= 1
\t\tif pn[w*uint64(bps)+uint64(k)] {
\t\t\tv |= 1
\t\t}
\t}
\treturn v
}

// pnSymbolsForEpoch — PN-поток эпохи, упакованный в M-арные символы окон
// (M8: bps=3). Используется TX для sync-преамбулы и холостого потока
// (ленивый IdleBit при S~1-2 сэмпла на окно был бы квадратично дорогим).
func pnSymbolsForEpoch(master []byte, epoch uint64, nWin uint64, bps int) []uint8 {
\tbits := IdleBitsForEpoch(master, epoch, nWin*uint64(bps))
\tout := make([]uint8, nWin)
\tfor w := range out {
\t\tout[w] = pnWindowSym(bits, uint64(w), bps)
\t}
\treturn out
}
""", 1))
patch("internal/chaossync/schedule.go", sch)

# ================= session.go =================
ses = []

ses.append(("imports", """import (
\t"fmt"
\t"sync"
\t"time"
)""",
"""import (
\t"fmt"
\t"math/bits"
\t"sync"
\t"time"
)""", 1))

ses.append(("config-struct", """type Config struct {
\tMaster   []byte // мастер-ключ звена (из файла, 0600; НЕ из argv)
\tRate     int    // сэмплов/сек, 50..4000 (по умолч. 200)
\tEpochSec uint64 // T — период мутации f_k, секунд (по умолч. 32)
\tCoupling Fxp    // c — параметр связи Pecora–Carroll (по умолч. 0.85)
\tSymbolS  int    // S — сэмплов на символ (по умолч. 32)
\tDelta    Fxp    // δ — амплитуда возмущения (по умолч. 2^-8)
\tBatch    int    // сэмплов на UDP-датаграмму, 1..8 (по умолч. 4)
}""",
"""type Config struct {
\tMaster   []byte // мастер-ключ звена (из файла, 0600; НЕ из argv)
\tRate     int    // сэмплов/сек, 50..4000 (по умолч. 200)
\tEpochSec uint64 // T — период мутации f_k, секунд (по умолч. 32)
\tCoupling Fxp    // c — параметр связи Pecora–Carroll (по умолч. 0.85)
\tSymbolS  int    // S — сэмплов на символ для CSK (по умолч. 32)
\tDelta    Fxp    // δ — амплитуда возмущения (по умолч. 2^-8; в M8 — полуразмах созвездия)
\tBatch    int    // сэмплов на UDP-датаграмму, 1..8 (по умолч. 4)
\t// Modulation — физический слой символа: ModulationM8 (дефолт, ~×83 к CSK
\t// по Э-B) или ModulationCSK (fallback на деградацию канала).
\tModulation Modulation
\t// M8S — сэмплов на символ в режиме M8 (по умолч. m8DefaultS — подобрано
\t// замером символьного BER против запаса rep3-FEC, m8_test.go/agent.md).
\tM8S int
}""", 1))

ses.append(("withdefaults-m8s", """\tif c.Batch <= 0 {
\t\tc.Batch = 4
\t}
\tif c.Batch > 8 {
\t\tc.Batch = 8
\t}
\treturn c
}""",
"""\tif c.Batch <= 0 {
\t\tc.Batch = 4
\t}
\tif c.Batch > 8 {
\t\tc.Batch = 8
\t}
\tif c.Modulation == ModulationM8 && c.M8S <= 0 {
\t\tc.M8S = m8DefaultS
\t}
\treturn c
}

// symParams — бит на символьное окно и сэмплов на окно активной модуляции:
// M8 → (3, M8S), CSK → (1, SymbolS).
func (c Config) symParams() (bps, symS int) {
\td := c.withDefaults()
\tif d.Modulation == ModulationCSK {
\t\treturn 1, d.SymbolS
\t}
\treturn 3, d.M8S
}""", 1))

ses.append(("validate", """// epochLen — сэмплов в эпохе. ОБЯЗАНО быть кратным SymbolS (см. Validate).
func (c Config) epochLen() uint64 { d := c.withDefaults(); return uint64(d.Rate) * d.EpochSec }

// Validate — fail-closed проверка конфигурации звена.
func (c Config) Validate() error {
\tif uint64(c.Rate)*c.EpochSec%uint64(c.SymbolS) != 0 {
\t\treturn fmt.Errorf("chaossync: rate*epochSec=%d не кратно symbolS=%d — подберите T кратно %g с",
\t\t\tuint64(c.Rate)*c.EpochSec, c.SymbolS, float64(c.SymbolS)/float64(c.Rate))
\t}
\tif uint64(c.Rate)*c.EpochSec/uint64(c.SymbolS) < 2*syncWinK {
\t\treturn fmt.Errorf("chaossync: в эпохе меньше %d окон — sync-преамбула не оставляет места данным", 2*syncWinK)
\t}
\treturn nil
}""",
"""// epochLen — сэмплов в эпохе. ОБЯЗАНО быть кратным числу сэмплов на символ
// активной модуляции (см. Validate).
func (c Config) epochLen() uint64 { d := c.withDefaults(); return uint64(d.Rate) * d.EpochSec }

// Validate — fail-closed проверка конфигурации звена.
func (c Config) Validate() error {
\t_, symS := c.symParams()
\tif symS < 1 || symS > 128 {
\t\treturn fmt.Errorf("chaossync: сэмплов на символ %d вне [1,128]", symS)
\t}
\tif uint64(c.Rate)*c.EpochSec%uint64(symS) != 0 {
\t\treturn fmt.Errorf("chaossync: rate*epochSec=%d не кратно symbolS=%d — подберите T кратно %g с",
\t\t\tuint64(c.Rate)*c.EpochSec, symS, float64(symS)/float64(c.Rate))
\t}
\tif uint64(c.Rate)*c.EpochSec/uint64(symS) < 2*syncWinK {
\t\treturn fmt.Errorf("chaossync: в эпохе меньше %d окон — sync-преамбула не оставляет места данным", 2*syncWinK)
\t}
\treturn nil
}""", 1))

ses.append(("endpoint-fields", """\tcfg Config
\ttxM []byte
\trxM []byte
\tmod Modulator
""",
"""\tcfg  Config
\ttxM  []byte
\trxM  []byte
\tmod  Modulator // CSK-слой (fallback)
\tm8   Modem8    // M8-слой (дефолт по Э-B)
\tbps  int       // бит на символьное окно: 3 (M8) | 1 (CSK)
\tsymS int       // сэмплов на символьное окно: M8S (M8) | SymbolS (CSK)
""", 1))

ses.append(("tx-fields", """\t// TX
\ttxEpoch   uint64
\ttxParams  *FieldParams
\ttxX       [Sites]Fxp
\ttxCount   uint64
\tenc       *frameEncoder
\tlastSym   uint64
\tlastBit   bool
\tlastSymOK bool
""",
"""\t// TX
\ttxEpoch   uint64
\ttxParams  *FieldParams
\ttxX       [Sites]Fxp
\ttxCount   uint64
\tenc       *frameEncoder
\tlastSym   uint64
\tlastBit   bool
\tlastSymV  uint8 // последний выбранный символ окна (M8)
\tlastSymOK bool
\ttxIdle    []uint8 // кэш PN-символов эпохи (только M8; CSK берёт IdleBit лениво)
""", 1))

ses.append(("newendpoint", """\treturn &Endpoint{
\t\tcfg:    cfg,
\t\ttxM:    dirMaster(cfg.Master, txDir),
\t\trxM:    dirMaster(cfg.Master, rxDir),
\t\tmod:    Modulator{Delta: cfg.Delta, S: cfg.SymbolS},
\t\tenc:    newFrameEncoder(),
\t\tparser: newFrameParser(),
\t\tmode:   rxHunt,
\t}""",
"""\tbps, symS := cfg.symParams()
\treturn &Endpoint{
\t\tcfg:    cfg,
\t\ttxM:    dirMaster(cfg.Master, txDir),
\t\trxM:    dirMaster(cfg.Master, rxDir),
\t\tmod:    Modulator{Delta: cfg.Delta, S: cfg.SymbolS},
\t\tm8:     NewModem8(cfg.Delta, symS),
\t\tbps:    bps,
\t\tsymS:   symS,
\t\tenc:    newFrameEncoder(),
\t\tparser: newFrameParser(),
\t\tmode:   rxHunt,
\t}""", 1))

ses.append(("nextdatagram", """\tif e.txParams == nil {
\t\te.txEpoch = EpochFor(now, e.cfg.EpochSec)
\t\te.txParams = DeriveField(e.txM, e.txEpoch)
\t\te.txX = EpochInit(e.txM, e.txEpoch)
\t\te.txCount = 0
\t}
\tq := make([]uint16, 0, e.cfg.Batch)
\tfor i := 0; i < e.cfg.Batch; i++ {
\t\tif e.txCount >= e.cfg.epochLen() {
\t\t\te.txEpoch++
\t\t\te.txParams = DeriveField(e.txM, e.txEpoch)
\t\t\te.txX = EpochInit(e.txM, e.txEpoch)
\t\t\te.txCount = 0
\t\t\te.lastSymOK = false
\t\t}
\t\te.txParams.Step(&e.txX)
\t\tsymIdx := e.txCount / uint64(e.cfg.SymbolS)
\t\tvar bit bool
\t\tif e.lastSymOK && symIdx == e.lastSym {
\t\t\tbit = e.lastBit
\t\t} else {
\t\t\tif symIdx < syncWinK {
\t\t\t\t// sync-преамбула: keyed слово, кадровый поток не трогаем
\t\t\t\tbit = IdleBit(e.txM, e.txEpoch, symIdx)
\t\t\t} else {
\t\t\t\tbit = e.enc.nextBit(e.txM, e.txEpoch, symIdx)
\t\t\t}
\t\t\te.lastSym, e.lastBit, e.lastSymOK = symIdx, bit, true
\t\t}
\t\te.mod.Perturb(&e.txX, e.txParams.Drive, bit)
\t\tq = append(q, Quantize16(e.txX[e.txParams.Drive]))
\t\te.txCount++
\t}""",
"""\tif e.txParams == nil {
\t\te.txEpoch = EpochFor(now, e.cfg.EpochSec)
\t\te.txParams = DeriveField(e.txM, e.txEpoch)
\t\te.txX = EpochInit(e.txM, e.txEpoch)
\t\te.txCount = 0
\t\te.txRefreshIdleLocked()
\t}
\tq := make([]uint16, 0, e.cfg.Batch)
\tfor i := 0; i < e.cfg.Batch; i++ {
\t\tif e.txCount >= e.cfg.epochLen() {
\t\t\te.txEpoch++
\t\t\te.txParams = DeriveField(e.txM, e.txEpoch)
\t\t\te.txX = EpochInit(e.txM, e.txEpoch)
\t\t\te.txCount = 0
\t\t\te.lastSymOK = false
\t\t\te.txRefreshIdleLocked()
\t\t}
\t\te.txParams.Step(&e.txX)
\t\tsymIdx := e.txCount / uint64(e.symS)
\t\tif e.bps == 3 {
\t\t\tvar sym uint8
\t\t\tif e.lastSymOK && symIdx == e.lastSym {
\t\t\t\tsym = e.lastSymV
\t\t\t} else {
\t\t\t\tif symIdx < syncWinK {
\t\t\t\t\t// sync-преамбула: ключевое слово, кадровый поток не трогаем
\t\t\t\t\tsym = e.txIdle[symIdx]
\t\t\t\t} else {
\t\t\t\t\tsym = e.enc.nextSymM8(e.txM, e.txEpoch, symIdx, e.txIdle)
\t\t\t\t}
\t\t\t\te.lastSym, e.lastSymV, e.lastSymOK = symIdx, sym, true
\t\t\t}
\t\t\te.m8.Perturb(&e.txX, e.txParams.Drive, sym)
\t\t} else {
\t\t\tvar bit bool
\t\t\tif e.lastSymOK && symIdx == e.lastSym {
\t\t\t\tbit = e.lastBit
\t\t\t} else {
\t\t\t\tif symIdx < syncWinK {
\t\t\t\t\t// sync-преамбула: keyed слово, кадровый поток не трогаем
\t\t\t\t\tbit = IdleBit(e.txM, e.txEpoch, symIdx)
\t\t\t\t} else {
\t\t\t\t\tbit = e.enc.nextBit(e.txM, e.txEpoch, symIdx)
\t\t\t\t}
\t\t\t\te.lastSym, e.lastBit, e.lastSymOK = symIdx, bit, true
\t\t\t}
\t\t\te.mod.Perturb(&e.txX, e.txParams.Drive, bit)
\t\t}
\t\tq = append(q, Quantize16(e.txX[e.txParams.Drive]))
\t\te.txCount++
\t}""", 1))

# хелпер txRefreshIdleLocked — сразу после NextDatagram (перед "// --- RX")
ses.append(("txrefresh", """\tdat := make([]byte, 2*len(q))
\tEncodeSamples(dat, q)
\treturn dat
}

// --- RX ------------------------------------------------------------------""",
"""\tdat := make([]byte, 2*len(q))
\tEncodeSamples(dat, q)
\treturn dat
}

// txRefreshIdleLocked — перегенерация кэша PN-символов эпохи на границе
// (только M8). Кэш покрывает и sync-преамбулу, и холостой поток эпохи.
func (e *Endpoint) txRefreshIdleLocked() {
\tif e.bps != 3 {
\t\treturn
\t}
\te.txIdle = pnSymbolsForEpoch(e.txM, e.txEpoch, e.cfg.epochLen()/uint64(e.symS), e.bps)
}

// --- RX ------------------------------------------------------------------""", 1))

ses.append(("adoptnext", """\te.desyncGrace = syncWinK * e.cfg.SymbolS
\te.pnBits = IdleBitsForEpoch(e.rxM, e.rxEpoch, e.cfg.epochLen()/uint64(e.cfg.SymbolS))""",
"""\te.desyncGrace = syncWinK * e.symS
\te.pnBits = IdleBitsForEpoch(e.rxM, e.rxEpoch, e.cfg.epochLen()/uint64(e.symS)*uint64(e.bps))""", 1))

ses.append(("boundary-pn", """\tpn := IdleBitsForEpoch(e.rxM, ne, e.cfg.epochLen()/uint64(e.cfg.SymbolS))""",
"""\tpn := IdleBitsForEpoch(e.rxM, ne, e.cfg.epochLen()/uint64(e.symS)*uint64(e.bps))""", 1))

ses.append(("boundary-candsyncok", """\t\tif !candSyncOK(&cand, pn, uint64(e.cfg.SymbolS)) {""",
"""\t\tif !e.candSyncOK(&cand, pn) {""", 1))

ses.append(("need-syms", """\tneed := syncWinK * uint64(e.cfg.SymbolS)""",
"""\tneed := syncWinK * uint64(e.symS)""", 2))

ses.append(("candsyncok-method", """// candSyncOK — вердикт по sync-преамбуле: каждое ПОЛНОЕ окно из первых
// syncWinK обязано декодировать бит ключевого PN-потока эпохи. Дата-окна
// (≥syncWinK) не проверяются — их содержимое заранее неизвестно.
func candSyncOK(c *boundaryCand, pn []bool, S uint64) bool {
\tfor w := uint64(0); w < syncWinK && (w+1)*S <= uint64(len(c.resid)); w++ {
\t\tif w >= uint64(len(pn)) {
\t\t\tbreak
\t\t}
\t\tvar acc Fxp
\t\tfor k := w * S; k < (w+1)*S; k++ {
\t\t\tacc = acc.Add(c.resid[k])
\t\t}
\t\tif (acc > 0) != pn[w] {
\t\t\treturn false
\t\t}
\t}
\treturn true
}""",
"""// candSyncOK — вердикт по sync-преамбуле: каждое ПОЛНОЕ окно из первых
// syncWinK обязано декодировать символ ключевого PN-потока эпохи (CSK: 1 бит;
// M8: все 3 бита — преамбула втрое сильнее при той же длине в окнах).
// Дата-окна (≥syncWinK) не проверяются — их содержимое заранее неизвестно.
func (e *Endpoint) candSyncOK(c *boundaryCand, pn []bool) bool {
\tS := uint64(e.symS)
\tfor w := uint64(0); w < syncWinK && (w+1)*S <= uint64(len(c.resid)); w++ {
\t\tif (w+1)*uint64(e.bps) > uint64(len(pn)) {
\t\t\tbreak
\t\t}
\t\tvar acc Fxp
\t\tfor k := w * S; k < (w+1)*S; k++ {
\t\t\tacc = acc.Add(c.resid[k])
\t\t}
\t\tif e.bps == 3 {
\t\t\tif e.m8.Classify(acc) != pnWindowSym(pn, w, e.bps) {
\t\t\t\treturn false
\t\t\t}
\t\t} else if (acc > 0) != pn[w] {
\t\t\treturn false
\t\t}
\t}
\treturn true
}""", 1))

ses.append(("pend-candsyncok", """\t\tif candSyncOK(c, e.pendPN, uint64(e.cfg.SymbolS)) {""",
"""\t\tif e.candSyncOK(c, e.pendPN) {""", 1))

ses.append(("adoptcand", """\te.desyncGrace = syncWinK * e.cfg.SymbolS
\te.highRun = 0
\te.m.Spikes++
\te.pnBits = IdleBitsForEpoch(e.rxM, c.epoch, e.cfg.epochLen()/uint64(e.cfg.SymbolS))
\te.pnEpoch = c.epoch
\te.pnOK = true
\te.pendOn = false
\te.pendCands = nil
\te.pendOld = nil
\tS := uint64(e.cfg.SymbolS)
\te.symAcc = 0
\tfor k, rk := range c.resid {
\t\te.symAcc = e.symAcc.Add(rk)
\t\tif (uint64(k) % S) == S-1 {
\t\t\tbit := e.symAcc > 0
\t\t\te.commitWindowLocked(bit, uint64(k)/S, c.epoch)
\t\t\te.symAcc = 0
\t\t}
\t}""",
"""\te.desyncGrace = syncWinK * e.symS
\te.highRun = 0
\te.m.Spikes++
\te.pnBits = IdleBitsForEpoch(e.rxM, c.epoch, e.cfg.epochLen()/uint64(e.symS)*uint64(e.bps))
\te.pnEpoch = c.epoch
\te.pnOK = true
\te.pendOn = false
\te.pendCands = nil
\te.pendOld = nil
\tS := uint64(e.symS)
\te.symAcc = 0
\tfor k, rk := range c.resid {
\t\te.symAcc = e.symAcc.Add(rk)
\t\tif (uint64(k) % S) == S-1 {
\t\t\tif e.bps == 3 {
\t\t\t\te.commitWindowLocked(e.m8.Classify(e.symAcc), uint64(k)/S, c.epoch)
\t\t\t} else if e.symAcc > 0 {
\t\t\t\te.commitWindowLocked(1, uint64(k)/S, c.epoch)
\t\t\t} else {
\t\t\t\te.commitWindowLocked(0, uint64(k)/S, c.epoch)
\t\t\t}
\t\t\te.symAcc = 0
\t\t}
\t}""", 1))

ses.append(("rxdecode", """// rxDecodeSymbolLocked — интеграция residual по окну; при завершении окна —
// commitWindowLocked. Вызывается с rxCount = индекс ТЕКУЩЕГО сэмпла эпохи.
func (e *Endpoint) rxDecodeSymbolLocked(r Fxp) {
\tS := uint64(e.cfg.SymbolS)
\tsymIdx := e.rxCount / S
\te.symAcc = e.symAcc.Add(r)
\tif (e.rxCount % S) != S-1 {
\t\treturn
\t}
\tbit := e.symAcc > 0
\te.symAcc = 0
\te.commitWindowLocked(bit, symIdx, e.rxEpoch)
}""",
"""// rxDecodeSymbolLocked — интеграция residual по окну; при завершении окна —
// commitWindowLocked. Вызывается с rxCount = индекс ТЕКУЩЕГО сэмпла эпохи.
// CSK: знак суммы → бит. M8: классификация суммы в уровень → 3 бита.
func (e *Endpoint) rxDecodeSymbolLocked(r Fxp) {
\tS := uint64(e.symS)
\tsymIdx := e.rxCount / S
\te.symAcc = e.symAcc.Add(r)
\tif (e.rxCount % S) != S-1 {
\t\treturn
\t}
\tif e.bps == 3 {
\t\tsym := e.m8.Classify(e.symAcc)
\t\te.symAcc = 0
\t\te.commitWindowLocked(sym, symIdx, e.rxEpoch)
\t\treturn
\t}
\tbit := e.symAcc > 0
\te.symAcc = 0
\tif bit {
\t\te.commitWindowLocked(1, symIdx, e.rxEpoch)
\t} else {
\t\te.commitWindowLocked(0, symIdx, e.rxEpoch)
\t}
}""", 1))

ses.append(("commitwindow", """// commitWindowLocked — завершённое символьное окно. Окна 0..syncWinK-1 —
// sync-преамбула (сверка с ключевым словом, в парсер НЕ идут). Остальные —
// в парсер кадров + PN-сверка для BER-сторожа.
func (e *Endpoint) commitWindowLocked(bit bool, symIdx uint64, epoch uint64) {
\tif symIdx < syncWinK {
\t\tif e.pnOK && symIdx < uint64(len(e.pnBits)) {
\t\t\te.m.SyncTot++
\t\t\tif bit != e.pnBits[symIdx] {
\t\t\t\te.m.SyncBad++
\t\t\t}
\t\t}
\t\treturn
\t}
\tmarkerFound := e.parser.Feed(bit, epoch)
\tif markerFound {
\t\te.berCorrectMarkerLocked(symIdx)
\t}
\tif !e.parser.InFrame() && e.pnOK && symIdx < uint64(len(e.pnBits)) {
\t\twant := e.pnBits[symIdx]
\t\te.m.BerDen++
\t\te.berWin++
\t\tif bit != want {
\t\t\te.m.BerNum++
\t\t\te.berWinBad++
\t\t}
\t\tif e.berWin >= berWatchN {
\t\t\tif e.berWinBad > berWatchBad {
\t\t\t\t// PN не сходится. Если residual живой — уехала фаза, а не
\t\t\t\t// поле: ждём следующую границу вместо полного перезахвата.
\t\t\t\te.berWin, e.berWinBad = 0, 0
\t\t\t\tif e.lastMs > 0 && e.lastMs < 0.0002 {
\t\t\t\t\te.phaseKnown = false
\t\t\t\t} else {
\t\t\t\t\te.startHuntLocked(e.lastNow)
\t\t\t\t\treturn
\t\t\t\t}
\t\t\t}
\t\t\te.berWin, e.berWinBad = 0, 0
\t\t}
\t}""",
"""// commitWindowLocked — завершённое символьное окно; sym — символ окна
// (CSK: 0/1; M8: 0..7). Окна 0..syncWinK-1 — sync-преамбула (сверка с
// ключевым словом, в парсер НЕ идут). Остальные — в парсер кадров (по bps
// бит, старшим первым) + PN-сверка для BER-сторожа.
func (e *Endpoint) commitWindowLocked(sym uint8, symIdx uint64, epoch uint64) {
\tbps := uint64(e.bps)
\tif symIdx < syncWinK {
\t\tif e.pnOK && (symIdx+1)*bps <= uint64(len(e.pnBits)) {
\t\t\te.m.SyncTot += bps
\t\t\te.m.SyncBad += uint64(bits.OnesCount8(sym ^ pnWindowSym(e.pnBits, symIdx, e.bps)))
\t\t}
\t\treturn
\t}
\tfor k := e.bps - 1; k >= 0; k-- {
\t\tif e.parser.Feed((sym>>uint(k))&1 == 1, epoch) {
\t\t\te.berCorrectMarkerLocked(symIdx)
\t\t}
\t}
\tif !e.parser.InFrame() && e.pnOK && (symIdx+1)*bps <= uint64(len(e.pnBits)) {
\t\tbad := uint64(bits.OnesCount8(sym ^ pnWindowSym(e.pnBits, symIdx, e.bps)))
\t\te.m.BerDen += bps
\t\te.m.BerNum += bad
\t\te.berWin += bps
\t\te.berWinBad += bad
\t\tif e.berWin >= berWatchN {
\t\t\tif e.berWinBad > berWatchBad {
\t\t\t\t// PN не сходится. Если residual живой — уехала фаза, а не
\t\t\t\t// поле: ждём следующую границу вместо полного перезахвата.
\t\t\t\te.berWin, e.berWinBad = 0, 0
\t\t\t\tif e.lastMs > 0 && e.lastMs < 0.0002 {
\t\t\t\t\te.phaseKnown = false
\t\t\t\t} else {
\t\t\t\t\te.startHuntLocked(e.lastNow)
\t\t\t\t\treturn
\t\t\t\t}
\t\t\t}
\t\t\te.berWin, e.berWinBad = 0, 0
\t\t}
\t}""", 1))

ses.append(("bercorrect", """// berCorrectMarkerLocked — ретро-коррекция BER: окна маркера перед curSym
// были посчитаны как PN-ошибки, хотя это биты публичного маркера.
func (e *Endpoint) berCorrectMarkerLocked(curSym uint64) {
\tif curSym < 23 || !e.pnOK {
\t\treturn
\t}
\tvar num, den uint64
\tfor j := uint64(0); j < 23; j++ {
\t\tw := curSym - 23 + j
\t\tif w >= uint64(len(e.pnBits)) {
\t\t\tbreak
\t\t}
\t\tmbit := (frameMarker>>uint(23-j))&1 == 1
\t\tden++
\t\tif e.pnBits[w] != mbit {
\t\t\tnum++
\t\t}
\t}""",
"""// berCorrectMarkerLocked — ретро-коррекция BER: окна маркера перед curSym
// были посчитаны как PN-ошибки, хотя это биты публичного маркера. Маркер —
// 24 бита = 24/bps окон; текущее окно уже «в кадре» (в PN-BER не посчитано),
// корректируем предыдущие 24/bps−1 окон (CSK: 23, M8: 7).
func (e *Endpoint) berCorrectMarkerLocked(curSym uint64) {
\tspan := uint64(24/e.bps - 1)
\tif curSym < span || !e.pnOK {
\t\treturn
\t}
\tbps := uint64(e.bps)
\tvar num, den uint64
\tfor j := uint64(0); j < span; j++ {
\t\tw := curSym - span + j
\t\tfor k := uint64(0); k < bps; k++ {
\t\t\tpb := w*bps + k
\t\t\tif pb >= uint64(len(e.pnBits)) {
\t\t\t\tbreak
\t\t\t}
\t\t\tmbit := (frameMarker>>uint(23-(j*bps+k)))&1 == 1
\t\t\tden++
\t\t\tif e.pnBits[pb] != mbit {
\t\t\t\tnum++
\t\t\t}
\t\t}
\t}""", 1))

patch("internal/chaossync/session.go", ses)
print("PATCH TASK2 (modem+schedule+session) DONE")
