import sys

p = 'internal/chaossync/session.go'
lines = open(p, encoding='utf-8').read().split(chr(10))

out = []
i = 0
blocks = 0
fieldslines = 0
while i < len(lines):
    ln = lines[i]
    st = ln.strip()
    # поля Dbg* и их leading-комментарий
    if st.startswith('Dbg') or st.startswith('// ВРЕМЕННО: отладка'):
        fieldslines += 1
        i += 1
        continue
    # блоки if e.DbgOn { ... } (со сбалансированными скобками)
    if 'if e.DbgOn {' in ln:
        depth = 0
        j = i
        while j < len(lines):
            depth += lines[j].count('{') - lines[j].count('}')
            if depth == 0:
                break
            j += 1
        i = j + 1
        blocks += 1
        continue
    out.append(ln)
    i += 1

open(p, 'w', encoding='utf-8').write(chr(10).join(out))
print('removed DbgOn blocks:', blocks, 'field/comment lines:', fieldslines)
if blocks == 0 or fieldslines == 0:
    print('WARNING: ничего не удалено — проверь якоря')
    sys.exit(1)
