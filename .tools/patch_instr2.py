import re

p = 'internal/chaossync/session.go'
s = open(p).read()

# 1. debug-журнал в Endpoint (после DbgRxBits)
m = re.search(r"\tDbgRxBits \[\]bool\n", s)
assert m, 'DbgRxBits field not found'
s = s[:m.end()] + "\tDbgLog    []string\n" + s[m.end():]

# 2. лог принятий границы (после m.Spikes++)
needle = "\te.m.Spikes++\n"
m = re.search(re.escape(needle), s)
assert m, 'spikes++ not found'
ins = needle + "\tif e.DbgOn {\n\t\te.DbgLog = append(e.DbgLog, fmt.Sprintf(\"ADOPT yTotal=%d j_resid=%d epoch=%d\", e.yTotal, len(c.resid), c.epoch))\n\t}\n"
s = s[:m.end()] + ins[len(needle):] + s[m.end():]

# 3. лог ошибочных sync-окон
old = '''\tif symIdx < syncWinK {
\t\tif e.pnOK && symIdx < uint64(len(e.pnBits)) {
\t\t\te.m.SyncTot++
\t\t\tif bit != e.pnBits[symIdx] {
\t\t\t\te.m.SyncBad++
\t\t\t}
\t\t}
\t\treturn
\t}'''
new = '''\tif symIdx < syncWinK {
\t\tif e.pnOK && symIdx < uint64(len(e.pnBits)) {
\t\t\te.m.SyncTot++
\t\t\tif bit != e.pnBits[symIdx] {
\t\t\t\te.m.SyncBad++
\t\t\t\tif e.DbgOn {
\t\t\t\t\te.DbgLog = append(e.DbgLog, fmt.Sprintf("SYNCERR yTotal=%d epoch=%d symIdx=%d", e.yTotal, epoch, symIdx))
\t\t\t\t}
\t\t\t}
\t\t}
\t\treturn
\t}'''
assert old in s, 'sync check block not found'
s = s.replace(old, new, 1)

# 4. лог PN-ошибок дата-окон
old = '''\t\tif bit != want {
\t\t\te.m.BerNum++
\t\t\te.berWinBad++
\t\t}'''
assert old in s, 'pn err block not found'
new = '''\t\tif bit != want {
\t\t\te.m.BerNum++
\t\t\te.berWinBad++
\t\t\tif e.DbgOn {
\t\t\t\te.DbgLog = append(e.DbgLog, fmt.Sprintf("PNERR yTotal=%d epoch=%d symIdx=%d", e.yTotal, epoch, symIdx))
\t\t\t}
\t\t}'''
s = s.replace(old, new, 1)

open(p, 'w').write(s)
print('instrumented v2 OK')
