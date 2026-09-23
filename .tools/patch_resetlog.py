import sys

p = 'internal/chaossync/session.go'
lines = open(p, encoding='utf-8').read().splitlines()
nl = chr(10)

out = []
added_field = False
added_log = False
for ln in lines:
    st = ln.strip()
    # поле DbgResetY сразу после DbgRxW
    if (not added_field) and st == 'DbgRxW    []uint64':
        out.append(ln)
        out.append('\tDbgResetY []uint64')
        added_field = True
        continue
    # лог перед parser.Reset()
    if (not added_log) and st.startswith('e.parser.Reset()'):
        out.append('\tif e.DbgOn {')
        out.append('\t\te.DbgResetY = append(e.DbgResetY, e.yTotal)')
        out.append('\t}')
        out.append(ln)
        added_log = True
        continue
    out.append(ln)

if not (added_field and added_log):
    print('ANCHOR MISS', added_field, added_log)
    sys.exit(1)
open(p, 'w', encoding='utf-8').write(nl.join(out) + nl)
print('reset log instrumented OK')
