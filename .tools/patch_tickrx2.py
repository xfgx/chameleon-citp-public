p = 'internal/chaossync/session.go'
s = open(p, encoding='utf-8').read()

# Находим TickRx и заменяем целиком (по сбалансированным скобкам).
sig = 'func (e *Endpoint) TickRx(now time.Time) {'
i = s.index(sig)
j = s.index('{', i)
depth = 0
k = j
while True:
    ch = s[k]
    if ch == '{':
        depth += 1
    elif ch == '}':
        depth -= 1
        if depth == 0:
            break
    k += 1
old = s[i:k+1]
assert 'rxFreeRunLocked' in old, 'TickRx body unexpected'

T = chr(9)
nl = chr(10)
new = (
'// TickRx — один такт локальных часов приёмника: обработать сэмплы из' + nl +
'// джиттер-буфера ПО ПОРЯДКУ. Вызывается драйвером с периодом DatagramInterval().' + nl +
'//' + nl +
'// Пустая очередь — джиттер (датаграмма ещё в пути), а НЕ потеря: поле шагаем' + nl +
'// ТОЛЬКО по реальным сэмплам, счётчик/фаза не сдвигаются. Поле дискретно по' + nl +
'// индексу сэмпла, а не по стенке — пауза безопасна и НЕ ломает выравнивание.' + nl +
'// Реальная потеря вскрывается residual\'ом (resync), а каждая эпоха и так' + nl +
'// сбрасывает обе стороны в EpochInit — переходный сбой лечится сам.' + nl +
'func (e *Endpoint) TickRx(now time.Time) {' + nl +
T + 'e.mu.Lock()' + nl +
T + 'defer e.mu.Unlock()' + nl +
T + 'if !e.huntInit {' + nl +
T + T + 'e.startHuntLocked(now)' + nl +
T + '}' + nl +
T + '// Догоняем бэклог после всплеска: до 2*Batch за такт, если очередь длинная.' + nl +
T + 'limit := e.cfg.Batch' + nl +
T + 'if len(e.rxQ) > 2*e.cfg.Batch {' + nl +
T + T + 'limit = 2 * e.cfg.Batch' + nl +
T + '}' + nl +
T + 'for i := 0; i < limit && len(e.rxQ) > 0; i++ {' + nl +
T + T + 'y := Dequantize16(e.rxQ[0])' + nl +
T + T + 'e.rxQ = e.rxQ[1:]' + nl +
T + T + 'e.rxSampleLocked(y, now)' + nl +
T + '}' + nl +
'}')

s = s[:i] + new + s[k+1:]
open(p, 'w', encoding='utf-8').write(s)
print('TickRx free-run removed; process-in-order installed')
