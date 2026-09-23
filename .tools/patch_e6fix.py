import sys

# --- 1) session.go: делаем акцессоры Config отказоустойчивыми к нулевым полям ---
p = 'internal/chaossync/session.go'
s = open(p, encoding='utf-8').read()

reps = [
    ('func (c Config) epochLen() uint64 { return uint64(c.Rate) * c.EpochSec }',
     'func (c Config) epochLen() uint64 { d := c.withDefaults(); return uint64(d.Rate) * d.EpochSec }'),
    ('func (c Config) Interval() time.Duration { return time.Second / time.Duration(c.Rate) }',
     'func (c Config) Interval() time.Duration { return time.Second / time.Duration(c.withDefaults().Rate) }'),
    ('func (c Config) DatagramInterval() time.Duration { return c.Interval() * time.Duration(c.Batch) }',
     'func (c Config) DatagramInterval() time.Duration { d := c.withDefaults(); return time.Second / time.Duration(d.Rate) * time.Duration(d.Batch) }'),
]
for old, new in reps:
    assert old in s, 'session anchor: ' + old[:50]
    s = s.replace(old, new, 1)
open(p, 'w', encoding='utf-8').write(s)
print('session.go: Config accessors hardened')

# --- 2) lab main.go: задаём поля явно в конфигах cmdSync и cmdMutate ---
p2 = 'tools/chaossync-lab/main.go'
s2 = open(p2, encoding='utf-8').read()

sync_old = 'cfg := chaossync.Config{Master: labMaster, EpochSec: *T}'
sync_new = 'cfg := chaossync.Config{Master: labMaster, EpochSec: *T, Rate: 200, SymbolS: 32, Batch: 4, Coupling: chaossync.MustDecimal("0.85")}'
assert sync_old in s2, 'cmdSync cfg anchor'
s2 = s2.replace(sync_old, sync_new, 1)

mut_old = 'cfg := chaossync.Config{Master: labMaster, EpochSec: T}'
mut_new = 'cfg := chaossync.Config{Master: labMaster, EpochSec: T, Rate: 200, SymbolS: 32, Batch: 4, Coupling: chaossync.MustDecimal("0.85")}'
assert mut_old in s2, 'cmdMutate cfg anchor'
s2 = s2.replace(mut_old, mut_new, 1)

open(p2, 'w', encoding='utf-8').write(s2)
print('lab main.go: cmdSync/cmdMutate configs explicit')
