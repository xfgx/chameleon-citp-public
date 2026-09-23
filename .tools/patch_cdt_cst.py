import sys
nl = chr(10)
T = chr(9)

# ---------- 1) новый файл internal/chaossync/cdt_cst.go ----------
cst_go = nl.join([
'package chaossync',
'',
'// cdt_cst.go — CST (Continuity Session Ticket) для CDT: логическая',
'// идентичность туннеля поверх эфемерных фрагментов и мутирующих эпох.',
'//',
'// В CDT каждый фрагмент запечатан AEAD-ключом эпохи (выводится из master),',
'// а глобальный seq держит порядок сквозь ротации. CST добавляет поверх этого',
'// ЯВНОЕ доказательство непрерывности: AAD каждого фрагмента = sid эпохи',
'// направления, sid_m = KDF(master, "cdt-cst-v1", dir, m). Тег никогда не',
'// передаётся по сети — обе стороны выводят его локально, поэтому на проводе',
'// формат не меняется (nonce||ct), а фрагмент эпохи m доказывает знание всей',
'// цепочки идентичности, а не только data-ключа эпохи.',
'//',
'// Модель угроз (как у chaossync cst.go): компрометация sid одной эпохи не',
'// раскрывает sid других (независимый KDF на эпоху); replay фрагмента чужой',
'// эпохи отбрасывается (nonce-окно эпохи + AAD эпохи). Компрометация только',
'// data-ключа эпохи без master не даёт подделывать фрагменты (нет sid).',
'//',
'// CST включён во всех РОТАЦИОННЫХ конструкторах (NewRotatingFragmenter/',
'// NewRotatingDefragmenter/NewStream — боевой туннель). Burst-режим',
'// (фиксированная эпоха, лаборатория) остаётся без CST.',
'',
'import "encoding/binary"',
'',
'const cdtCstLabel = "cdt-cst-v1"',
'',
'// cdtCstAAD — AAD фрагмента эпохи: sid_m направления, усечённый до 16 байт.',
'// Не передаётся по сети; выводится обеими сторонами локально и побитово',
'// одинаково (чистый KDF, как весь chaossync/CDT).',
'func cdtCstAAD(master []byte, epoch uint64, dir string) []byte {',
T + 'return epochSeed(master, cdtLabel(cdtCstLabel, dir), epoch)[:16]',
'}',
'',
'// TunnelID — стабильный отпечаток идентичности туннеля для журналов обеих',
'// сторон: первые 8 байт цепочки от master и направления. Не зависит от',
'// эпохи (переживает ротации), не раскрывает ключ. Обе стороны живого',
'// туннеля обязаны показать одинаковый TunnelID; чужой master/направление',
'// дают другое значение.',
'func TunnelID(master []byte, dir string) uint64 {',
T + 'sid := epochSeed(master, cdtLabel(cdtCstLabel+"-tunnel", dir), 0)',
T + 'return binary.BigEndian.Uint64(sid[:8])',
'}',
''])
open('internal/chaossync/cdt_cst.go', 'w', encoding='utf-8').write(cst_go + nl)
print('cdt_cst.go written')

# ---------- 2) правки internal/chaossync/cdt.go ----------
p = 'internal/chaossync/cdt.go'
s = open(p, encoding='utf-8').read()

def rep(old, new, cnt=1):
    global s
    assert s.count(old) == cnt, 'anchor count %d != %d: %r' % (s.count(old), cnt, old[:60])
    s = s.replace(old, new, cnt)

# 2.1 Fragmenter struct: поля cst/aad
rep(T+'geom    *GeometrySource'+nl+T+'aead    cipher.AEAD'+nl+T+'seq     uint64 // ГЛОБАЛЬНЫЙ номер фрагмента (не сбрасывается при ротации)',
    T+'geom    *GeometrySource'+nl+T+'aead    cipher.AEAD'+nl+T+'cst     bool   // CST включён (ротационный режим): AAD = sid эпохи'+nl+T+'aad     []byte // текущий CST-AAD (пересчитывается на ротации)'+nl+T+'seq     uint64 // ГЛОБАЛЬНЫЙ номер фрагмента (не сбрасывается при ротации)')

# 2.2 NewRotatingFragmenter: включить CST
rep(T+'return &Fragmenter{master: master, cfg: cfg.withDefaults(), T: T, epoch: ep,'+nl+T+T+'geom: NewGeometrySource(master, ep, cfg), aead: cdtDataAEAD(master, ep, cfg)}',
    T+'return &Fragmenter{master: master, cfg: cfg.withDefaults(), T: T, epoch: ep,'+nl+T+T+'geom: NewGeometrySource(master, ep, cfg), aead: cdtDataAEAD(master, ep, cfg),'+nl+T+T+'cst: true, aad: cdtCstAAD(master, ep, cfg.Dir)}')

# 2.3 Fragmenter.TickEpoch: пересчёт AAD при ротации
rep(T+T+'f.aead = cdtDataAEAD(f.master, ep, f.cfg)'+nl+T+T+'f.hasCur = false // недобранная геометрия сбрасывается при ротации',
    T+T+'f.aead = cdtDataAEAD(f.master, ep, f.cfg)'+nl+T+T+'if f.cst {'+nl+T+T+T+'f.aad = cdtCstAAD(f.master, ep, f.cfg.Dir)'+nl+T+T+'}'+nl+T+T+'f.hasCur = false // недобранная геометрия сбрасывается при ротации')

# 2.4 seal: AAD вместо nil
rep(T+'wire := f.aead.Seal(nil, nonce[:], plain, nil)',
    T+'wire := f.aead.Seal(nil, nonce[:], plain, f.aad)')

# 2.5 epochSink: поле aad
rep('type epochSink struct {'+nl+T+'geom  *GeometrySource'+nl+T+'aead  cipher.AEAD',
    'type epochSink struct {'+nl+T+'geom  *GeometrySource'+nl+T+'aead  cipher.AEAD'+nl+T+'aad   []byte // CST: sid эпохи (nil = лабораторный burst-режим)')

# 2.6 newEpochSink: параметр cst
rep('func newEpochSink(master []byte, epoch uint64, cfg GeomConfig) *epochSink {'+nl+T+'return &epochSink{'+nl+T+T+'geom:  NewGeometrySource(master, epoch, cfg),'+nl+T+T+'aead:  cdtDataAEAD(master, epoch, cfg),'+nl+T+T+'ahead: make(map[string]struct{}),'+nl+T+'}'+nl+'}',
    'func newEpochSink(master []byte, epoch uint64, cfg GeomConfig, cst bool) *epochSink {'+nl+T+'s := &epochSink{'+nl+T+T+'geom:  NewGeometrySource(master, epoch, cfg),'+nl+T+T+'aead:  cdtDataAEAD(master, epoch, cfg),'+nl+T+T+'ahead: make(map[string]struct{}),'+nl+T+'}'+nl+T+'if cst {'+nl+T+T+'s.aad = cdtCstAAD(master, epoch, cfg.Dir)'+nl+T+'}'+nl+T+'return s'+nl+'}')

# 2.7 Defragmenter struct: поле cst
rep(T+'T             uint64'+nl+T+'epoch         uint64'+nl+T+'cur           *epochSink',
    T+'T             uint64'+nl+T+'epoch         uint64'+nl+T+'cst           bool // CST включён (ротационный режим)'+nl+T+'cur           *epochSink')

# 2.8 NewDefragmenter: burst без CST
rep(T+'d.cur = newEpochSink(master, epoch, cfg)',
    T+'d.cur = newEpochSink(master, epoch, cfg, false)')

# 2.9 NewRotatingDefragmenter: CST on
rep(T+'d := &Defragmenter{master: master, cfg: cfg.withDefaults(), T: T, epoch: ep,'+nl+T+T+'bySeq: map[uint64][]byte{}, window: 8192, reorderWindow: 64}'+nl+T+'d.cur = newEpochSink(d.master, ep, cfg)',
    T+'d := &Defragmenter{master: master, cfg: cfg.withDefaults(), T: T, epoch: ep,'+nl+T+T+'cst: true, bySeq: map[uint64][]byte{}, window: 8192, reorderWindow: 64}'+nl+T+'d.cur = newEpochSink(d.master, ep, cfg, true)')

# 2.10 Defragmenter.TickEpoch: новая эпоха с флагом cst
rep(T+T+'d.cur = newEpochSink(d.master, ep, d.cfg)',
    T+T+'d.cur = newEpochSink(d.master, ep, d.cfg, d.cst)')

# 2.11 Ingest/IngestRaw: Open с AAD (2 места)
rep('s.aead.Open(nil, nonce, ct, nil)', 's.aead.Open(nil, nonce, ct, s.aad)', cnt=2)

open(p, 'w', encoding='utf-8').write(s)
print('cdt.go patched (CST)')

# ---------- 3) новый тест internal/chaossync/cdt_cst_test.go ----------
tst = nl.join([
'package chaossync',
'',
'// cdt_cst_test.go — CST для CDT: явная идентичность туннеля поверх ротаций',
'// эпох. Проверяем: свой туннель работает, чужой master отбрасывается,',
'// фрагмент без CST (лабораторный) не проходит в CST-туннель, replay-окно',
'// straddle ведёт себя задокументированно, TunnelID стабилен и различителен.',
'',
'import (',
T+'"bytes"',
T+'"testing"',
T+'"time"',
')',
'',
'var (',
T+'cstMasterA = bytes.Repeat([]byte{0x42}, 32)',
T+'cstMasterB = bytes.Repeat([]byte{0x43}, 32)',
T+'cstCfg     = GeomConfig{}.withDefaults()',
T+'cstT       = uint64(8)',
T+'cstBase    = time.Unix(1_700_000_000, 0)',
')',
'',
'// Свой туннель с CST работает; чужой master отбрасывается fail-closed.',
'func TestCDTCstWrongMasterRejected(t *testing.T) {',
T+'frag := NewRotatingFragmenter(cstMasterA, cstCfg, cstT, cstBase)',
T+'good := NewRotatingDefragmenter(cstMasterA, cstCfg, cstT, cstBase)',
T+'bad := NewRotatingDefragmenter(cstMasterB, cstCfg, cstT, cstBase)',
'',
T+'frag.Push(bytes.Repeat([]byte{0xAB}, 5000))',
T+'wire, _, ok := frag.Emit()',
T+'if !ok {',
T+T+'t.Fatal("emit failed")',
T+'}',
T+'if !good.Ingest(wire) {',
T+T+'t.Fatal("свой фрагмент отброшен при CST")',
T+'}',
T+'if bad.Ingest(wire) {',
T+T+'t.Fatal("чужой master прошёл при CST")',
T+'}',
'}',
'',
'// CST реально связывает фрагмент с цепочкой идентичности: фрагмент от',
'// лабораторного (без CST) фрагментера с тем же master и той же эпохой',
'// обязан быть отброшен ротационным дефрагментером — data-ключ и nonce',
'// совпадают, отличается только AAD.',
'func TestCDTCstBindsContinuity(t *testing.T) {',
T+'ep := EpochFor(cstBase, cstT)',
T+'lab := NewFragmenter(cstMasterA, ep, cstCfg) // burst: без CST',
T+'tun := NewRotatingDefragmenter(cstMasterA, cstCfg, cstT, cstBase)',
'',
T+'lab.Push(bytes.Repeat([]byte{0xCD}, 3000))',
T+'wire, _, ok := lab.Emit()',
T+'if !ok {',
T+T+'t.Fatal("emit failed")',
T+'}',
T+'if tun.Ingest(wire) {',
T+T+'t.Fatal("фрагмент без CST прошёл в CST-туннель")',
T+'}',
'}',
'',
'// Replay: фрагмент эпохи m, не доставленный вовремя, принимается в окне',
'// straddle (m = prev при m+1 — задокументированная грейс-зона), повтор того',
'// же провода отбрасывается (nonce поглощён), а после выхода эпохи из окна',
'// фрагмент забывается окончательно.',
'func TestCDTCstCrossEpochReplay(t *testing.T) {',
T+'frag := NewRotatingFragmenter(cstMasterA, cstCfg, cstT, cstBase)',
T+'defrag := NewRotatingDefragmenter(cstMasterA, cstCfg, cstT, cstBase)',
'',
T+'frag.Push(bytes.Repeat([]byte{0xEF}, 4000))',
T+'wire, _, ok := frag.Emit()',
T+'if !ok {',
T+T+'t.Fatal("emit failed")',
T+'}',
T+'// straddle: m+1 — запоздавший фрагмент эпохи m принимается (дизайн)',
T+'t1 := cstBase.Add(time.Duration(cstT+1) * time.Second)',
T+'frag.TickEpoch(t1)',
T+'defrag.TickEpoch(t1)',
T+'if !defrag.Ingest(wire) {',
T+T+'t.Fatal("straggler границы эпохи отброшен в окне straddle")',
T+'}',
T+'// реальный replay (тот же провод дважды) — отброшен (nonce поглощён)',
T+'if defrag.Ingest(wire) {',
T+T+'t.Fatal("повторный фрагмент прошёл (replay внутри окна)")',
T+'}',
T+'// выход из окна: m+2 — эпоха m забыта',
T+'t2 := cstBase.Add(time.Duration(2*cstT+1) * time.Second)',
T+'defrag.TickEpoch(t2)',
T+'if defrag.Ingest(wire) {',
T+T+'t.Fatal("фрагмент забытой эпохи прошёл")',
T+'}',
'}',
'',
'// TunnelID: стабилен, одинаков у обеих сторон одного туннеля, различает',
'// master и направление, не зависит от эпохи.',
'func TestCDTTunnelID(t *testing.T) {',
T+'a1 := TunnelID(cstMasterA, "c2n")',
T+'if a1 != TunnelID(cstMasterA, "c2n") {',
T+T+'t.Fatal("TunnelID нестабилен")',
T+'}',
T+'if a1 == TunnelID(cstMasterB, "c2n") {',
T+T+'t.Fatal("TunnelID не различает master")',
T+'}',
T+'if a1 == TunnelID(cstMasterA, "n2c") {',
T+T+'t.Fatal("TunnelID не различает направление")',
T+'}',
'}',
''])
open('internal/chaossync/cdt_cst_test.go', 'w', encoding='utf-8').write(tst + nl)
print('cdt_cst_test.go written')
print('PATCH_CDT_CST_DONE')
