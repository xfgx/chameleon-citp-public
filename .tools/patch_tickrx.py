p = 'internal/chaossync/session.go'
s = open(p, encoding='utf-8').read()
T = chr(9)
nl = chr(10)

old = (T + T + '} else {' + nl +
    T + T + T + 'e.m.InferredLoss++' + nl +
    T + T + T + 'e.rxFreeRunLocked()' + nl +
    T + T + '}')
assert s.count(old) == 1, 'tickrx else anchor count=%d' % s.count(old)

new = (T + T + '} else if e.phaseKnown {' + nl +
    T + T + T + '// разрыв на установленном звене = потеря: free-run, счётчик\n' +
    T + T + T + '// остаётся выровненным, поле ре-синхронизируется на границе.\n' +
    T + T + T + 'e.m.InferredLoss++' + nl +
    T + T + T + 'e.rxFreeRunLocked()' + nl +
    T + T + '}' + nl +
    T + T + '// до захвата фазы пустая очередь = «данных ещё нет» (нода молчит\n' +
    T + T + '// до доказательства ключа) — ждём, часы сэмплов не двигаем.')

s = s.replace(old, new, 1)
open(p, 'w', encoding='utf-8').write(s)
print('tickrx underrun gate installed OK')
