import re

p = 'internal/chaossync/session.go'
s = open(p).read()

# 1. DbgRxY рядом с DbgRxBits
m = re.search(r"\tDbgRxBits \[\]bool\n", s)
assert m, 'DbgRxBits not found'
s = s[:m.end()] + "\tDbgRxY    []uint64\n" + s[m.end():]

# 2. записываем yTotal при commitWindowLocked (рядом с DbgRxBits append)
old = '''\tif e.DbgOn {
\t\te.DbgRxBits = append(e.DbgRxBits, bit)
\t}'''
assert old in s, 'dbg append not found'
new = '''\tif e.DbgOn {
\t\te.DbgRxBits = append(e.DbgRxBits, bit)
\t\te.DbgRxY = append(e.DbgRxY, e.yTotal)
\t}'''
s = s.replace(old, new, 1)

open(p, 'w').write(s)
print('DbgRxY instrumented')
