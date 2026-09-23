p = 'internal/chaossync/session.go'
lines = open(p, encoding='utf-8').read().split('\n')
out = []
i = 0
removed_case = False
removed_s = False
while i < len(lines):
    ln = lines[i]
    # Удаляем объявление S (использовалось только в удаляемой ветке).
    if (not removed_s and ln.strip() == 'S := uint64(e.cfg.SymbolS)'
            and i > 0 and 'need :=' in lines[i-1]):
        removed_s = True
        i += 1
        continue
    # Удаляем ветку раннего принятия по 2 окнам: case + комментарий + adopt.
    if (not removed_case and '>= 2*S:' in ln and 'len(alive) == 1' in ln):
        removed_case = True
        i += 3
        continue
    out.append(ln)
    i += 1
open(p, 'w', encoding='utf-8').write('\n'.join(out))
print('removed_case', removed_case, 'removed_s', removed_s)
