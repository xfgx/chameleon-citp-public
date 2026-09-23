import sys
nl = chr(10)
T = chr(9)

p = 'internal/chaossync/cdt.go'
s = open(p, encoding='utf-8').read()

# --- импорт time ---
if '\t"time"\n' not in s:
    s = s.replace('\t"errors"\n', '\t"errors"\n\t"time"\n', 1)
    assert '\t"time"\n' in s, 'time import'

# --- 1) Fragmenter struct: добавить master/cfg/T/epoch ---
old_fs = ('type Fragmenter struct {' + nl +
    T + 'geom    *GeometrySource' + nl +
    T + 'aead    cipher.AEAD' + nl +
    T + 'seq     uint64' + nl +
    T + 'pending []byte' + nl +
    T + 'cur     PacketGeom' + nl +
    T + 'hasCur  bool' + nl +
    '}')
assert old_fs in s, 'Fragmenter struct anchor'
new_fs = ('type Fragmenter struct {' + nl +
    T + 'master  []byte' + nl +
    T + 'cfg     GeomConfig' + nl +
    T + 'T       uint64 // сек на эпоху; 0 = фиксированная эпоха (burst/тест)' + nl +
    T + 'epoch   uint64' + nl +
    T + 'geom    *GeometrySource' + nl +
    T + 'aead    cipher.AEAD' + nl +
    T + 'seq     uint64 // ГЛОБАЛЬНЫЙ номер фрагмента (не сбрасывается при ротации)' + nl +
    T + 'pending []byte' + nl +
    T + 'cur     PacketGeom' + nl +
    T + 'hasCur  bool' + nl +
    '}')
s = s.replace(old_fs, new_fs, 1)

# --- 2) NewFragmenter: заполнить master/cfg/epoch + добавить ротацию после ---
old_nf = ('func NewFragmenter(master []byte, epoch uint64, cfg GeomConfig) *Fragmenter {' + nl +
    T + 'return &Fragmenter{geom: NewGeometrySource(master, epoch, cfg), aead: cdtDataAEAD(master, epoch)}' + nl +
    '}')
assert old_nf in s, 'NewFragmenter anchor'
new_nf = ('func NewFragmenter(master []byte, epoch uint64, cfg GeomConfig) *Fragmenter {' + nl +
    T + 'return &Fragmenter{master: master, cfg: cfg.withDefaults(), epoch: epoch,' + nl +
    T + T + 'geom: NewGeometrySource(master, epoch, cfg), aead: cdtDataAEAD(master, epoch)}' + nl +
    '}' + nl + nl +
    '// NewRotatingFragmenter — непрерывный туннель: эпоха следует за wall-clock,' + nl +
    '// геометрия+ключ мутируют по T; глобальный seq и буфер payload не сбрасываются.' + nl +
    'func NewRotatingFragmenter(master []byte, cfg GeomConfig, T uint64, now time.Time) *Fragmenter {' + nl +
    T + 'ep := EpochFor(now, T)' + nl +
    T + 'return &Fragmenter{master: master, cfg: cfg.withDefaults(), T: T, epoch: ep,' + nl +
    T + T + 'geom: NewGeometrySource(master, ep, cfg), aead: cdtDataAEAD(master, ep)}' + nl +
    '}' + nl + nl +
    '// TickEpoch — ротация при смене wall-clock эпохи. Вызывать драйверу по тикеру.' + nl +
    'func (f *Fragmenter) TickEpoch(now time.Time) {' + nl +
    T + 'if f.T == 0 {' + nl +
    T + T + 'return' + nl +
    T + '}' + nl +
    T + 'ep := EpochFor(now, f.T)' + nl +
    T + 'if ep != f.epoch {' + nl +
    T + T + 'f.epoch = ep' + nl +
    T + T + 'f.geom = NewGeometrySource(f.master, ep, f.cfg)' + nl +
    T + T + 'f.aead = cdtDataAEAD(f.master, ep)' + nl +
    T + T + 'f.hasCur = false // недобранная геометрия сбрасывается при ротации' + nl +
    T + '}' + nl +
    '}')
s = s.replace(old_nf, new_nf, 1)

# --- 3) Defragmenter: переписать секцию от struct до конца файла ---
dstart = s.index('type Defragmenter struct {')
s = s[:dstart]

newd = [
'type epochSink struct {',
T + 'geom  *GeometrySource',
T + 'aead  cipher.AEAD',
T + 'ahead map[string]struct{} // ожидаемые (ещё не совпавшие) nonce этой эпохи',
T + 'gen   uint64             // сколько nonce сгенерировано',
T + 'used  uint64             // сколько совпало',
'}',
'',
'func newEpochSink(master []byte, epoch uint64, cfg GeomConfig) *epochSink {',
T + 'return &epochSink{',
T + T + 'geom:  NewGeometrySource(master, epoch, cfg),',
T + T + 'aead:  cdtDataAEAD(master, epoch),',
T + T + 'ahead: make(map[string]struct{}),',
T + '}',
'}',
'',
'// fill — скользящее окно ожидаемых nonce: держим window впереди поглощённых.',
'func (s *epochSink) fill(window uint64) {',
T + 'for s.gen < s.used+window {',
T + T + 'g := s.geom.Next()',
T + T + 's.ahead[string(g.Nonce[:])] = struct{}{}',
T + T + 's.gen++',
T + '}',
'}',
'',
'// Defragmenter — нода: собирает поток из фрагментов. Знает хаос-узор (та же',
'// GeometrySource на эпоху). Держит текущую и предыдущую эпоху (straddle на',
'// границе ротации). Сборка — по глобальному seq изнутри запечатанного блока,',
'// поэтому поток непрерывен сквозь ротации эпох. Шум/чужие отбрасываются fail-closed.',
'type Defragmenter struct {',
T + 'master  []byte',
T + 'cfg     GeomConfig',
T + 'T       uint64',
T + 'epoch   uint64',
T + 'cur     *epochSink',
T + 'prev    *epochSink',
T + 'deliver uint64           // следующий ГЛОБАЛЬНЫЙ seq к выдаче',
T + 'bySeq   map[uint64][]byte // по глобальному seq',
T + 'ready   [][]byte',
T + 'window  uint64',
'}',
'',
'// NewDefragmenter — фиксированная эпоха (burst/тест).',
'func NewDefragmenter(master []byte, epoch uint64, cfg GeomConfig) *Defragmenter {',
T + 'd := &Defragmenter{master: master, cfg: cfg.withDefaults(), epoch: epoch,',
T + T + 'bySeq: map[uint64][]byte{}, window: 8192}',
T + 'd.cur = newEpochSink(master, epoch, cfg)',
T + 'return d',
'}',
'',
'// NewRotatingDefragmenter — непрерывный туннель: эпоха следует за wall-clock.',
'func NewRotatingDefragmenter(master []byte, cfg GeomConfig, T uint64, now time.Time) *Defragmenter {',
T + 'ep := EpochFor(now, T)',
T + 'd := &Defragmenter{master: master, cfg: cfg.withDefaults(), T: T, epoch: ep,',
T + T + 'bySeq: map[uint64][]byte{}, window: 8192}',
T + 'd.cur = newEpochSink(d.master, ep, cfg)',
T + 'return d',
'}',
'',
'// TickEpoch — ротация при смене wall-clock эпохи: текущая уходит в prev',
'// (продолжает принимать stragglers с границы), новая становится cur.',
'func (d *Defragmenter) TickEpoch(now time.Time) {',
T + 'if d.T == 0 {',
T + T + 'return',
T + '}',
T + 'ep := EpochFor(now, d.T)',
T + 'if ep != d.epoch {',
T + T + 'd.prev = d.cur',
T + T + 'd.cur = newEpochSink(d.master, ep, d.cfg)',
T + T + 'd.epoch = ep',
T + '}',
'}',
'',
'// Ingest — принять фрагмент с провода. true = опознан и расшифрован.',
'func (d *Defragmenter) Ingest(wire []byte) bool {',
T + 'if len(wire) < cdtNonceLen+cdtSeqLen+16 {',
T + T + 'return false',
T + '}',
T + 'nonce := wire[:cdtNonceLen]',
T + 'ct := wire[cdtNonceLen:]',
T + 'for _, s := range []*epochSink{d.cur, d.prev} {',
T + T + 'if s == nil {',
T + T + T + 'continue',
T + T + '}',
T + T + 's.fill(d.window)',
T + T + 'if _, ok := s.ahead[string(nonce)]; !ok {',
T + T + T + 'continue',
T + T + '}',
T + T + 'plain, err := s.aead.Open(nil, nonce, ct, nil)',
T + T + 'if err != nil {',
T + T + T + 'return false // nonce из расписания, но AEAD не сошёлся — чужой/повреждение',
T + T + '}',
T + T + 'if len(plain) < cdtSeqLen {',
T + T + T + 'return false',
T + T + '}',
T + T + 'gseq := binary.BigEndian.Uint64(plain)',
T + T + 'delete(s.ahead, string(nonce))',
T + T + 's.used++',
T + T + 'd.bySeq[gseq] = plain[cdtSeqLen:]',
T + T + 'd.drain()',
T + T + 'return true',
T + '}',
T + 'return false',
'}',
'',
'func (d *Defragmenter) drain() {',
T + 'for {',
T + T + 'chunk, ok := d.bySeq[d.deliver]',
T + T + 'if !ok {',
T + T + T + 'break',
T + T + '}',
T + T + 'delete(d.bySeq, d.deliver)',
T + T + 'd.ready = append(d.ready, chunk)',
T + T + 'd.deliver++',
T + '}',
'}',
'',
'// Next — следующий по глобальному порядку кусок payload.',
'func (d *Defragmenter) Next() []byte {',
T + 'if len(d.ready) == 0 {',
T + T + 'return nil',
T + '}',
T + 'c := d.ready[0]',
T + 'd.ready = d.ready[1:]',
T + 'return c',
'}',
]
s = s + nl.join(newd) + nl
open(p, 'w', encoding='utf-8').write(s)
print('cdt.go rotation v2 installed')
