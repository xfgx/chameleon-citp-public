import sys

p = 'internal/chaossync/session.go'
s = open(p, encoding='utf-8').read()
T = chr(9)
nl = chr(10)

# 1) поле rxQ после yValid
anchor_field = T + 'yValid     int'
assert anchor_field in s, 'field anchor'
s = s.replace(anchor_field, anchor_field + nl +
    T + 'rxQ        []uint16 // джиттер-буфер сэмплов (Э5, buffered path)', 1)

# 2) rxFreeRunLocked: счётчик-управляемый переход и в свободном беге
old_fr = ('func (e *Endpoint) rxFreeRunLocked() {' + nl +
    T + 'if e.mode == rxHunt {' + nl +
    T + T + 'for _, c := range e.hunt {' + nl +
    T + T + T + 'c.p.Step(&c.x)' + nl +
    T + T + '}' + nl +
    T + T + 'return' + nl +
    T + '}' + nl +
    T + 'e.rxParams.Step(&e.rxX)' + nl +
    T + 'e.rxCount++' + nl +
    '}')
assert old_fr in s, 'freerun anchor'
new_fr = ('func (e *Endpoint) rxFreeRunLocked() {' + nl +
    T + 'if e.mode == rxHunt {' + nl +
    T + T + 'for _, c := range e.hunt {' + nl +
    T + T + T + 'c.p.Step(&c.x)' + nl +
    T + T + '}' + nl +
    T + T + 'return' + nl +
    T + '}' + nl +
    T + '// свободный бег через разрыв: счётчик и границы эпох идут дальше,\n' +
    T + '// поле ре-синхронизируется сбросом в EpochInit на ближайшей границе.\n' +
    T + 'if e.phaseKnown && e.rxCount >= e.cfg.epochLen() {' + nl +
    T + T + 'e.adoptNextEpochLocked()' + nl +
    T + '}' + nl +
    T + 'e.rxParams.Step(&e.rxX)' + nl +
    T + 'e.rxCount++' + nl +
    '}')
s = s.replace(old_fr, new_fr, 1)

# 3) новые методы: джиттер-буферный приём. Вставляем после rxFreeRunLocked.
insert_after = new_fr
new_methods = nl + nl + '''// rxQCap — граница джиттер-буфера (сэмплов). ~2 секунды при rate=200.
const rxQCap = 8192

// EnqueueDatagram — приём с джиттер-буфером (Э5): декодирует датаграмму и
// ставит сэмплы в очередь БЕЗ немедленной обработки. Обработка идёт в TickRx
// по ЛОКАЛЬНЫМ часам приёмника — это отделяет часы сэмплов от джиттера сети.
// Джиттер прихода здесь — только метрика качества канала (DPI-профиль),
// а не сигнал потери. Потеря — это underrun очереди в TickRx.
func (e *Endpoint) EnqueueDatagram(dat []byte, now time.Time) {
\tvar q [8]uint16
\tn := DecodeSamples(dat, q[:])
\tif n == 0 {
\t\treturn
\t}
\te.mu.Lock()
\tdefer e.mu.Unlock()
\t// метрика джиттера по межприходным интервалам (информационная)
\tif e.hasArr {
\t\tper := e.cfg.DatagramInterval()
\t\tdev := now.Sub(e.lastArr) - per
\t\tif dev < 0 {
\t\t\tdev = -dev
\t\t}
\t\te.jitSumMs += float64(dev.Microseconds()) / 1000.0
\t\te.jitN++
\t}
\te.lastArr, e.hasArr = now, true
\te.rxQ = append(e.rxQ, q[:n]...)
\tif len(e.rxQ) > rxQCap {
\t\te.rxQ = e.rxQ[len(e.rxQ)-rxQCap:]
\t}
}

// TickRx — один такт локальных часов приёмника: обработать Batch сэмплов из
// джиттер-буфера. Вызывается драйвером с периодом DatagramInterval().
// Underrun (очередь пуста) = реальный разрыв: free-run, счётчик остаётся
// выровненным, поле ре-синхронизируется на ближайшей границе эпохи.
func (e *Endpoint) TickRx(now time.Time) {
\te.mu.Lock()
\tdefer e.mu.Unlock()
\tif !e.huntInit {
\t\te.startHuntLocked(now)
\t}
\tfor i := 0; i < e.cfg.Batch; i++ {
\t\tif len(e.rxQ) > 0 {
\t\t\ty := Dequantize16(e.rxQ[0])
\t\t\te.rxQ = e.rxQ[1:]
\t\t\te.rxSampleLocked(y, now)
\t\t} else {
\t\t\te.m.InferredLoss++
\t\t\te.rxFreeRunLocked()
\t\t}
\t}
}

// RxQueued — текущая глубина джиттер-буфера (сэмплы). Метрика канала.
func (e *Endpoint) RxQueued() int {
\te.mu.Lock()
\tdefer e.mu.Unlock()
\treturn len(e.rxQ)
}'''
assert insert_after in s, 'insert anchor'
s = s.replace(insert_after, insert_after + new_methods, 1)

open(p, 'w', encoding='utf-8').write(s)
print('jitter buffer installed OK')
