p = 'internal/chaossync/session.go'
s = open(p, encoding='utf-8').read()

# 1) поля-координаты окна
old_f = "\tDbgRxY    []uint64\n\tDbgLog    []string\n"
assert old_f in s, 'fields anchor'
s = s.replace(old_f,
    "\tDbgRxY    []uint64\n\tDbgTxW    []uint64\n\tDbgRxW    []uint64\n\tDbgLog    []string\n", 1)

# 2) TX: записываем координату окна рядом с битом
old_tx = "\t\t\tif e.DbgOn {\n\t\t\t\te.DbgTxBits = append(e.DbgTxBits, bit)\n\t\t\t}\n"
assert old_tx in s, 'tx anchor'
new_tx = ("\t\t\tif e.DbgOn {\n"
    "\t\t\t\te.DbgTxBits = append(e.DbgTxBits, bit)\n"
    "\t\t\t\tW := e.cfg.epochLen() / uint64(e.cfg.SymbolS)\n"
    "\t\t\t\te.DbgTxW = append(e.DbgTxW, e.txEpoch*W+symIdx)\n"
    "\t\t\t}\n")
s = s.replace(old_tx, new_tx, 1)

# 3) RX: записываем координату окна рядом с битом
old_rx = ("\tif e.DbgOn {\n\t\te.DbgRxBits = append(e.DbgRxBits, bit)\n"
    "\t\te.DbgRxY = append(e.DbgRxY, e.yTotal)\n\t}\n")
assert old_rx in s, 'rx anchor'
new_rx = ("\tif e.DbgOn {\n\t\te.DbgRxBits = append(e.DbgRxBits, bit)\n"
    "\t\te.DbgRxY = append(e.DbgRxY, e.yTotal)\n"
    "\t\tW := e.cfg.epochLen() / uint64(e.cfg.SymbolS)\n"
    "\t\te.DbgRxW = append(e.DbgRxW, epoch*W+symIdx)\n\t}\n")
s = s.replace(old_rx, new_rx, 1)

open(p, 'w', encoding='utf-8').write(s)
print('coords instrumented')
