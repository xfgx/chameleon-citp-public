import sys

p = 'internal/chaossync/session.go'
s = open(p, encoding='utf-8').read()

def find_func(src, sig):
    i = src.index(sig)
    j = src.index('{', i)
    depth = 0
    k = j
    while True:
        ch = src[k]
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return i, k + 1
        k += 1

new_rx = '''func (e *Endpoint) rxSampleLocked(y Fxp, now time.Time) {
\te.m.RxSamples++
\te.pushSampleLocked(y)
\tif e.mode == rxHunt {
\t\te.huntStepLocked(y, now)
\t\treturn
\t}
\tif e.pendOn {
\t\te.pendStepLocked(y)
\t\treturn
\t}

\t// Штатная граница эпохи — по выровненному захватом счётчику (фаза
\t// известна): детерминированный переход, идентичный TX (та же эпоха, то же
\t// EpochInit, тот же счётчик окон). Без спайка и replay: обе стороны
\t// сбрасываются в одно состояние в один сэмпл — нулевой транзиент.
\tif e.phaseKnown && e.rxCount >= e.cfg.epochLen() {
\t\te.adoptNextEpochLocked()
\t}

\tp := e.rxParams
\tp.Step(&e.rxX)
\tpred := e.rxX[p.Drive]
\tr := y.Sub(pred)

\tif r.Abs() > highRunThresh {
\t\te.highRun++
\t} else {
\t\te.highRun = 0
\t}
\t// Спайк-детекция границы — только при неизвестной фазе (первичный захват
\t// фазы либо перезахват после потерь на канале). В штатном режиме граница
\t// уходит по счётчику и спайк-логика не задействована.
\tif !e.phaseKnown && (r.Abs() > spikeThresh || e.highRun >= 3) {
\t\tif e.startBoundaryCheckLocked(r) {
\t\t\treturn // граница принята или pending запущен — сэмпл поглощён
\t\t}
\t\t// иначе — ложный спайк: продолжаем старое поле БЕЗ перезахвата.
\t}
\t// Штатная коррекция.
\te.rxX[p.Drive] = pred.Add(e.cfg.Coupling.Mul(r))

\t// Оконная статистика качества (residual ms).
\te.msSum = e.msSum.Add(r.Mul(r))
\te.msN++
\tif e.msN >= huntWindow {
\t\tavg := Fxp(int64(e.msSum) / int64(e.msN))
\t\te.lastMs = fxpToFloat(avg)
\t\tif avg > desyncMsThresh {
\t\t\te.desyncN += e.msN
\t\t} else {
\t\t\te.desyncN = 0
\t\t}
\t\te.msSum, e.msN = 0, 0
\t\tif e.desyncN >= desyncStreak {
\t\t\te.startHuntLocked(now)
\t\t\treturn
\t\t}
\t}

\tif e.phaseKnown {
\t\te.rxDecodeSymbolLocked(r) // декод с индексом ТЕКУЩЕГО сэмпла
\t}
\te.rxCount++
}

// adoptNextEpochLocked — детерминированный переход на следующую эпоху по
// выровненному счётчику: идентично TX (та же эпоха, то же EpochInit). Фаза
// остаётся известной; sync-преамбула новой эпохи верифицирует переход
// (расхождение sync-слов = счётчик сбит → desync-сторож перезахватит).
func (e *Endpoint) adoptNextEpochLocked() {
\te.rxEpoch++
\te.rxParams = DeriveField(e.rxM, e.rxEpoch)
\te.rxX = EpochInit(e.rxM, e.rxEpoch)
\te.rxCount = 0
\te.symAcc = 0
\te.highRun = 0
\te.pnBits = IdleBitsForEpoch(e.rxM, e.rxEpoch, e.cfg.epochLen()/uint64(e.cfg.SymbolS))
\te.pnEpoch = e.rxEpoch
\te.pnOK = true
\te.m.Spikes++
\tif e.DbgOn {
\t\te.DbgLog = append(e.DbgLog, fmt.Sprintf("ADOPT yTotal=%d j_resid=0 epoch=%d", e.yTotal, e.rxEpoch))
\t}
}
'''

a, b = find_func(s, 'func (e *Endpoint) rxSampleLocked(')
s = s[:a] + new_rx + s[b:]

# Потеря/разрыв: счётчик и состояние поля больше не доверяем → перезахват фазы.
old_gap = '''\t\te.yValid = 0
\t\tfor j := 0; j < missed; j++ {
\t\t\te.rxFreeRunLocked()
\t\t}'''
assert old_gap in s, 'gap anchor not found'
new_gap = '''\t\te.yValid = 0
\t\te.phaseKnown = false // счётчик сбит разрывом — граница снова по спайку
\t\tfor j := 0; j < missed; j++ {
\t\t\te.rxFreeRunLocked()
\t\t}'''
s = s.replace(old_gap, new_gap, 1)

open(p, 'w', encoding='utf-8').write(s)
print('counter-driven boundary installed')
