import sys
nl = chr(10)
T = chr(9)

# ============ cdt-client/main.go ============
pc = 'cmd/cdt-client/main.go'
sc = open(pc, encoding='utf-8').read()

# флаг -epoch -> -T
old_fl = T + 'epoch := flag.Uint64("epoch", 0, "эпоха геометрии/ключа (0 = wall-clock)")'
assert old_fl in sc, 'client flag anchor'
sc = sc.replace(old_fl, T + 'rotT := flag.Uint64("T", 8, "период мутации геометрии/ключа, сек — ротация эпох хаоса")', 1)

# убрать ep-блок
old_ep = (T + 'ep := *epoch' + nl +
	T + 'if ep == 0 {' + nl +
	T + T + 'ep = chaossync.EpochFor(time.Now(), 8)' + nl +
	T + '}' + nl)
assert old_ep in sc, 'client ep block anchor'
sc = sc.replace(old_ep, '', 1)

# NewFragmenter -> NewRotatingFragmenter
old_nf = T + 'frag := chaossync.NewFragmenter(master, ep, cfg)'
assert old_nf in sc, 'client NewFragmenter anchor'
sc = sc.replace(old_nf, T + 'frag := chaossync.NewRotatingFragmenter(master, cfg, *rotT, time.Now())', 1)

# TickEpoch в цикле
old_loop = T + 'for {' + nl + T + T + 'wire, g, ok := frag.Emit()'
assert old_loop in sc, 'client loop anchor'
sc = sc.replace(old_loop, T + 'for {' + nl + T + T + 'frag.TickEpoch(time.Now()) // ротация геометрии/ключа по эпохам' + nl + T + T + 'wire, g, ok := frag.Emit()', 1)

open(pc, 'w', encoding='utf-8').write(sc)
print('cdt-client: rotation wired')

# ============ cdt-server/main.go ============
ps = 'cmd/cdt-server/main.go'
ss = open(ps, encoding='utf-8').read()

old_fls = T + 'epoch := flag.Uint64("epoch", 0, "эпоха геометрии/ключа (0 = wall-clock)")'
assert old_fls in ss, 'server flag anchor'
ss = ss.replace(old_fls, T + 'rotT := flag.Uint64("T", 8, "период мутации геометрии/ключа, сек — ротация эпох хаоса")', 1)

old_eps = (T + 'ep := *epoch' + nl +
	T + 'if ep == 0 {' + nl +
	T + T + 'ep = chaossync.EpochFor(time.Now(), 8)' + nl +
	T + '}' + nl)
assert old_eps in ss, 'server ep block anchor'
ss = ss.replace(old_eps, '', 1)

old_nd = T + 'defrag := chaossync.NewDefragmenter(master, ep, cfg)'
assert old_nd in ss, 'server NewDefragmenter anchor'
ss = ss.replace(old_nd, T + 'defrag := chaossync.NewRotatingDefragmenter(master, cfg, *rotT, time.Now())', 1)

# лог-строка с ep
old_log = '*portBase+*portCount-1, bound, ep)'
assert old_log in ss, 'server log anchor'
ss = ss.replace(old_log, '*portBase+*portCount-1, bound, chaossync.EpochFor(time.Now(), *rotT))', 1)

# TickEpoch в главном ingest-цикле (та же goroutine -> без гонки)
old_ing = T + 'for dat := range datch {' + nl + T + T + 'totalFrags++'
assert old_ing in ss, 'server ingest anchor'
ss = ss.replace(old_ing, T + 'for dat := range datch {' + nl + T + T + 'defrag.TickEpoch(time.Now()) // ротация по эпохам (та же горутина, без гонки)' + nl + T + T + 'totalFrags++', 1)

open(ps, 'w', encoding='utf-8').write(ss)
print('cdt-server: rotation wired')
