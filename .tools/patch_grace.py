import sys

p = 'internal/chaossync/session.go'
lines = open(p, encoding='utf-8').read().splitlines()
nl = chr(10)
T = chr(9)  # tab

out = []
n_field = n_next = n_cand = n_msdec = n_gate = 0
i = 0
while i < len(lines):
    ln = lines[i]
    st = ln.strip()

    # 1) поле desyncGrace после desyncN в struct
    if n_field == 0 and st.startswith('desyncN') and st.endswith('int'):
        out.append(ln)
        out.append(T + 'desyncGrace int // остатковый грейс-период после перехода эпохи (сэмплы)')
        n_field += 1
        i += 1
        continue

    # 2) adoptNextEpochLocked: после highRun=0 (перед pnBits=IdleBitsForEpoch(rxM, rxEpoch,...))
    if (n_next == 0 and st == 'e.highRun = 0' and i + 1 < len(lines)
            and 'e.pnBits = IdleBitsForEpoch(e.rxM, e.rxEpoch' in lines[i+1]):
        out.append(ln)
        out.append(T + 'e.msSum, e.msN, e.desyncN = 0, 0, 0')
        out.append(T + 'e.desyncGrace = syncWinK * e.cfg.SymbolS')
        n_next += 1
        i += 1
        continue

    # 3) adoptCandidateLocked: после msSum=0 (пред. строка phaseKnown=true)
    if (n_cand == 0 and st == 'e.msSum, e.msN, e.desyncN = 0, 0, 0'
            and len(out) > 0 and out[-1].strip() == 'e.phaseKnown = true'):
        out.append(ln)
        out.append(T + 'e.desyncGrace = syncWinK * e.cfg.SymbolS')
        n_cand += 1
        i += 1
        continue

    # 4a) rxSampleLocked: декремент грейса перед накоплением ms
    if n_msdec == 0 and st == 'e.msSum = e.msSum.Add(r.Mul(r))':
        out.append(T + 'if e.desyncGrace > 0 {')
        out.append(T + T + 'e.desyncGrace--')
        out.append(T + '}')
        out.append(ln)
        n_msdec += 1
        i += 1
        continue

    # 4b) rxSampleLocked: гейт накопления desyncN грейсом
    if n_gate == 0 and st == 'if avg > desyncMsThresh {':
        out.append(T + T + 'if e.desyncGrace > 0 {')
        out.append(T + T + T + '// пограничный транзиент слежения — не рассинхрон: поле ре-конвергирует')
        out.append(T + T + '} else if avg > desyncMsThresh {')
        n_gate += 1
        i += 1
        continue

    out.append(ln)
    i += 1

print('field', n_field, 'next', n_next, 'cand', n_cand, 'msdec', n_msdec, 'gate', n_gate)
if not (n_field and n_next and n_cand and n_msdec and n_gate):
    print('ANCHOR MISS — не применено')
    sys.exit(1)
open(p, 'w', encoding='utf-8').write(nl.join(out) + nl)
print('grace installed OK')
