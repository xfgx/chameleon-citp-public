#!/usr/bin/env python3
# patch_task2_cmd.py — флаги -mod/-m8S в cmd/chaossync-server и cmd/chaossync-client.
import sys
ROOT = "/files/VPN"

def patch(path, edits):
    p = ROOT + "/" + path
    src = open(p, encoding="utf-8").read()
    for name, old, new in edits:
        n = src.count(old)
        if n != 1:
            print(f"FAIL {path} [{name}]: anchor found {n}", file=sys.stderr)
            sys.exit(1)
        src = src.replace(old, new, 1)
        print(f"  ok {path} [{name}]")
    open(p, "w", encoding="utf-8").write(src)

MODFLAG = '''\tmodFlag := flag.String("mod", "m8", "модуляция carrier: m8 (дефолт, ×83 по Э-B) | csk (fallback)")
\tm8s := flag.Int("m8S", 0, "M8: сэмплов на символ (0 — дефолт ядра)")
'''
MODPARSE = '''\tmod := chaossync.ModulationM8
\tswitch *modFlag {
\tcase "m8":
\tcase "csk":
\t\tmod = chaossync.ModulationCSK
\tdefault:
\t\tlog.Fatalf("fail-closed: неизвестная модуляция %q (m8|csk)", *modFlag)
\t}
'''
CFGLIT = '''\tcfg := chaossync.Config{
\t\tMaster:   master,
\t\tRate:     *rate,
\t\tEpochSec: *tSec,
\t\tCoupling: chaossync.MustDecimal(*coupling),
\t\tSymbolS:  *sym,
\t\tBatch:    *batch,
\t}'''
CFGLIT_NEW = MODPARSE + '''\tcfg := chaossync.Config{
\t\tMaster:     master,
\t\tRate:       *rate,
\t\tEpochSec:   *tSec,
\t\tCoupling:   chaossync.MustDecimal(*coupling),
\t\tSymbolS:    *sym,
\t\tBatch:      *batch,
\t\tModulation: mod,
\t\tM8S:        *m8s,
\t}'''

# server
patch("cmd/chaossync-server/main.go", [
    ("flags", '\tbatch := flag.Int("batch", 4, "сэмплов на UDP-датаграмму (1..8)")\n\tgenkey :=',
     '\tbatch := flag.Int("batch", 4, "сэмплов на UDP-датаграмму (1..8)")\n' + MODFLAG + '\tgenkey :='),
    ("cfg", CFGLIT, CFGLIT_NEW),
])
# client
patch("cmd/chaossync-client/main.go", [
    ("flags", '\tbatch := flag.Int("batch", 4, "сэмплов на датаграмму")\n',
     '\tbatch := flag.Int("batch", 4, "сэмплов на датаграмму")\n' + MODFLAG),
    ("cfg", CFGLIT, CFGLIT_NEW),
])
print("PATCH TASK2 CMD DONE")
