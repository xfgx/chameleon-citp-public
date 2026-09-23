package chaossync

// cdt.go — Chaos-Dispersed Transport (CDT): растворение потока, не маскировка.
//
// Философия spread-spectrum/DSSS в packet-домене под ограничение «только клиент
// + нода, без третьих сторон». Хаос НЕ несёт объём (физика синхронизации —
// низкая скорость, доказано Э1–Э5). Хаос диктует ГЕОМЕТРИЮ потока из общего
// синхронизированного состояния: на какой порт блока ноды уходит каждый
// фрагмент, какого он размера, с каким межпакетным интервалом, и время жизни
// каждого микро-потока (churn src-порта). Объём несёт быстрый AEAD data-plane
// (AES-256-GCM), ключи выводятся из того же хаос-материала.
//
// Для наблюдателя нет стабильного 5-tuple: один физический туннель выглядит как
// облако несвязуемых короткоживущих высокоэнтропийных обменов с разными портами
// по хаотическому расписанию. Nonce на проводе — случайный из хаос-расписания
// (не монотонный счётчик), поэтому сам не связываем. Собрать поток = решить
// задачу группировки фрагментов, ключ к которой — нестационарное хаос-состояние,
// не поддающееся реконструкции по построению (Э6). Это не мимикрия: мы не
// «выглядим как X», мы «не являемся ничем единым».
//
// Этическая граница без изменений: только собственный трафик двух сторон,
// никакого отравления чужих измерителей.

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"time"

	"chameleon/internal/chameleon"
)

const (
	cdtGeomLabel = "cdt-geom-v1"
	cdtDataLabel = "cdt-data-v1"
	cdtSeqLen    = 8  // байт номера фрагмента внутри запечатанного блока
	cdtNonceLen  = 12 // GCM nonce (на проводе, случайный)
)

// GeomConfig — блок портов ноды и пределы геометрии. Одинаков на обеих сторонах.
type GeomConfig struct {
	PortBase  int    // первый порт блока ноды (одна машина, адресное пространство портов)
	PortCount int    // число портов в блоке
	MinFrag   int    // байт полезной нагрузки на фрагмент (min)
	MaxFrag   int    // max
	MinGapUs  int    // мин. межпакетный интервал (мкс)
	MaxGapUs  int    // макс.
	MinFlow   int    // мин. фрагментов на один src-порт (микро-поток)
	MaxFlow   int    // макс.
	Dir       string // направление (разделение keystream двух сторон; "" = односторонний режим)
}

func (c GeomConfig) withDefaults() GeomConfig {
	if c.PortBase == 0 {
		c.PortBase = 4500
	}
	if c.PortCount <= 0 {
		c.PortCount = 144
	}
	if c.MinFrag <= 0 {
		c.MinFrag = 48
	}
	if c.MaxFrag <= 0 {
		c.MaxFrag = 1400
	}
	if c.MaxFrag < c.MinFrag {
		c.MaxFrag = c.MinFrag
	}
	if c.MinGapUs < 0 {
		c.MinGapUs = 0
	}
	if c.MaxGapUs <= 0 {
		c.MaxGapUs = 4000
	}
	if c.MaxGapUs < c.MinGapUs {
		c.MaxGapUs = c.MinGapUs
	}
	if c.MinFlow <= 0 {
		c.MinFlow = 1
	}
	if c.MaxFlow <= 0 {
		c.MaxFlow = 12
	}
	if c.MaxFlow < c.MinFlow {
		c.MaxFlow = c.MinFlow
	}
	return c
}

// PacketGeom — геометрия одного фрагмента (то, что видит наблюдатель на проводе).
type PacketGeom struct {
	DestPort int               // порт ноды из блока
	SrcPort  int               // эфемерный src-порт текущего микро-потока
	FragLen  int               // байт полезной нагрузки в этом фрагменте
	GapUs    int               // пауза перед отправкой (мкс)
	NewFlow  bool              // true → фрагмент открывает новый src-порт
	Nonce    [cdtNonceLen]byte // случайный nonce фрагмента (на проводе, не связываем)
}

// GeometrySource — детерминированный поток геометрии из хаос-ключевого материала.
// Обе синхронизированные стороны выводят идентично (тот же DRBG, тот же порядок
// вызовов). Геометрия мутирует вместе с эпохой хаоса (T).
type GeometrySource struct {
	d        *chameleon.DRBG
	cfg      GeomConfig
	flowLeft int
	curSrc   int
}

// NewGeometrySource — поток геометрии для (master, epoch). Побитово
// детерминирован на Windows и Linux (DRBG — SHA-512 counter, чистая арифметика).
func NewGeometrySource(master []byte, epoch uint64, cfg GeomConfig) *GeometrySource {
	return &GeometrySource{
		d:   chameleon.NewDRBG(epochSeed(master, cdtLabel(cdtGeomLabel, cfg.Dir), epoch), "geom"),
		cfg: cfg.withDefaults(),
	}
}

// Next — геометрия следующего фрагмента. Детерминированно по потоку DRBG.
func (g *GeometrySource) Next() PacketGeom {
	d := g.d
	c := g.cfg
	newFlow := false
	if g.flowLeft <= 0 {
		g.curSrc = 20000 + d.Intn(40000)
		g.flowLeft = c.MinFlow + d.Intn(c.MaxFlow-c.MinFlow+1)
		newFlow = true
	}
	g.flowLeft--
	var nonce [cdtNonceLen]byte
	copy(nonce[:], d.Bytes(cdtNonceLen))
	return PacketGeom{
		DestPort: c.PortBase + d.Intn(c.PortCount),
		SrcPort:  g.curSrc,
		FragLen:  c.MinFrag + d.Intn(c.MaxFrag-c.MinFrag+1),
		GapUs:    c.MinGapUs + d.Intn(c.MaxGapUs-c.MinGapUs+1),
		NewFlow:  newFlow,
		Nonce:    nonce,
	}
}

// cdtDataAEAD — AEAD data-plane: AES-256-GCM, ключ из хаос-материала эпохи.
// Это fail-closed дискриминатор: фрагмент с чужим ключом/шум не расшифруется и
// отбрасывается, нода на него не отвечает.
func cdtLabel(base, dir string) string {
	if dir == "" {
		return base
	}
	return base + "-" + dir
}

func cdtDataAEAD(master []byte, epoch uint64, cfg GeomConfig) cipher.AEAD {
	key := chameleon.NewDRBG(epochSeed(master, cdtLabel(cdtDataLabel, cfg.Dir), epoch), "data").Bytes(32)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err) // 32 байта — всегда валидный AES-256
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return aead
}

// --- сторона клиента: фрагментер -------------------------------------------

// Fragmenter растворяет поток в запечатанные фрагменты по хаос-геометрии.
type Fragmenter struct {
	master  []byte
	cfg     GeomConfig
	T       uint64 // сек на эпоху; 0 = фиксированная эпоха (burst/тест)
	epoch   uint64
	geom    *GeometrySource
	aead    cipher.AEAD
	cst     bool                          // CST включён (ротационный режим): AAD = sid эпохи
	aad     []byte                        // текущий CST-AAD (пересчитывается на ротации)
	geomFor func(epoch uint64) GeomConfig // автопилот: конфиг эпохи (nil = фиксированный cfg)
	seq     uint64                        // ГЛОБАЛЬНЫЙ номер фрагмента (не сбрасывается при ротации)
	pending []byte
	cur     PacketGeom
	hasCur  bool
}

func NewFragmenter(master []byte, epoch uint64, cfg GeomConfig) *Fragmenter {
	return &Fragmenter{master: master, cfg: cfg.withDefaults(), epoch: epoch,
		geom: NewGeometrySource(master, epoch, cfg), aead: cdtDataAEAD(master, epoch, cfg)}
}

// NewRotatingFragmenter — непрерывный туннель: эпоха следует за wall-clock,
// геометрия+ключ мутируют по T; глобальный seq и буфер payload не сбрасываются.
func NewRotatingFragmenter(master []byte, cfg GeomConfig, T uint64, now time.Time) *Fragmenter {
	ep := EpochFor(now, T)
	return &Fragmenter{master: master, cfg: cfg.withDefaults(), T: T, epoch: ep,
		geom: NewGeometrySource(master, ep, cfg), aead: cdtDataAEAD(master, ep, cfg),
		cst: true, aad: cdtCstAAD(master, ep, cfg.Dir)}
}

// TickEpoch — ротация при смене wall-clock эпохи. Вызывать драйверу по тикеру.
func (f *Fragmenter) TickEpoch(now time.Time) {
	if f.T == 0 {
		return
	}
	ep := EpochFor(now, f.T)
	if ep != f.epoch {
		f.epoch = ep
		cfg := f.cfg
		if f.geomFor != nil {
			cfg = f.geomFor(ep).withDefaults()
		}
		f.geom = NewGeometrySource(f.master, ep, cfg)
		f.aead = cdtDataAEAD(f.master, ep, cfg)
		if f.cst {
			f.aad = cdtCstAAD(f.master, ep, cfg.Dir)
		}
		f.hasCur = false // недобранная геометрия сбрасывается при ротации
	}
}

// Epoch — текущая эпоха фрагментера (для драйверов/метрик).
func (f *Fragmenter) Epoch() uint64 { return f.epoch }

// Push добавляет payload-байты в буфер на растворение.
func (f *Fragmenter) Push(p []byte) { f.pending = append(f.pending, p...) }

// Buffered — сколько payload-байт ожидает растворения.
func (f *Fragmenter) Buffered() int { return len(f.pending) }

// Emit — следующий фрагмент. Геометрия расходуется ровно один раз на выпущенный
// фрагмент (нода остаётся в ногу). ok=false, если payload меньше хаос-размера —
// геометрия при этом НЕ расходуется (та же геометрия применится к добивке).
func (f *Fragmenter) Emit() ([]byte, PacketGeom, bool) {
	if !f.hasCur {
		f.cur = f.geom.Next()
		f.hasCur = true
	}
	g := f.cur
	if len(f.pending) < g.FragLen {
		return nil, g, false // ждём ещё payload; геометрия не потрачена
	}
	f.hasCur = false
	chunk := f.pending[:g.FragLen]
	f.pending = f.pending[g.FragLen:]
	return f.seal(chunk, g.Nonce), g, true
}

// EmitFinal — добивка: выдать остаток даже если он меньше хаос-размера.
func (f *Fragmenter) EmitFinal() ([]byte, PacketGeom, bool) {
	if !f.hasCur {
		f.cur = f.geom.Next()
		f.hasCur = true
	}
	g := f.cur
	if len(f.pending) == 0 {
		return nil, g, false
	}
	f.hasCur = false
	chunk := f.pending
	f.pending = nil
	return f.seal(chunk, g.Nonce), g, true
}

func (f *Fragmenter) seal(chunk []byte, nonce [cdtNonceLen]byte) []byte {
	plain := make([]byte, cdtSeqLen+len(chunk))
	binary.BigEndian.PutUint64(plain, f.seq)
	copy(plain[cdtSeqLen:], chunk)
	wire := f.aead.Seal(nil, nonce[:], plain, f.aad)
	f.seq++
	// на проводе: случайный nonce ‖ шифротекст. nonce не связываем (хаос).
	out := make([]byte, 0, cdtNonceLen+len(wire))
	out = append(out, nonce[:]...)
	out = append(out, wire...)
	return out
}

// --- сторона ноды: дефрагментер --------------------------------------------

var (
	// ErrCDTBadFragment — фрагмент не опознан (шум/чужой/повреждён).
	ErrCDTBadFragment = errors.New("cdt: фрагмент не прошёл AEAD/не из расписания")
)

// Defragmenter — нода: собирает поток из фрагментов. Знает хаос-узор (та же
// GeometrySource): каждому ожидаемому фрагменту соответствует его nonce. Шум и
// чужие дейтаграммы отбрасываются fail-closed (AEAD-тег + nonce из расписания).
type epochSink struct {
	geom  *GeometrySource
	aead  cipher.AEAD
	aad   []byte              // CST: sid эпохи (nil = лабораторный burst-режим)
	ahead map[string]struct{} // ожидаемые (ещё не совпавшие) nonce этой эпохи
	gen   uint64              // сколько nonce сгенерировано
	used  uint64              // сколько совпало
}

func newEpochSink(master []byte, epoch uint64, cfg GeomConfig, cst bool) *epochSink {
	s := &epochSink{
		geom:  NewGeometrySource(master, epoch, cfg),
		aead:  cdtDataAEAD(master, epoch, cfg),
		ahead: make(map[string]struct{}),
	}
	if cst {
		s.aad = cdtCstAAD(master, epoch, cfg.Dir)
	}
	return s
}

// fill — скользящее окно ожидаемых nonce: держим window впереди поглощённых.
func (s *epochSink) fill(window uint64) {
	for s.gen < s.used+window {
		g := s.geom.Next()
		s.ahead[string(g.Nonce[:])] = struct{}{}
		s.gen++
	}
}

// Defragmenter — нода: собирает поток из фрагментов. Знает хаос-узор (та же
// GeometrySource на эпоху). Держит текущую и предыдущую эпоху (straddle на
// границе ротации). Сборка — по глобальному seq изнутри запечатанного блока,
// поэтому поток непрерывен сквозь ротации эпох. Шум/чужие отбрасываются fail-closed.
type Defragmenter struct {
	master        []byte
	cfg           GeomConfig
	T             uint64
	epoch         uint64
	cst           bool                          // CST включён (ротационный режим)
	geomFor       func(epoch uint64) GeomConfig // автопилот: конфиг эпохи (nil = cfg)
	cur           *epochSink
	prev          *epochSink
	deliver       uint64            // следующий ГЛОБАЛЬНЫЙ seq к выдаче
	bySeq         map[uint64][]byte // по глобальному seq
	ready         [][]byte
	window        uint64
	reorderWindow uint64 // сколько фрагментов ждём переупорядочивания, прежде чем признать дыру потерей
}

// NewDefragmenter — фиксированная эпоха (burst/тест).
func NewDefragmenter(master []byte, epoch uint64, cfg GeomConfig) *Defragmenter {
	d := &Defragmenter{master: master, cfg: cfg.withDefaults(), epoch: epoch,
		bySeq: map[uint64][]byte{}, window: 8192, reorderWindow: 64}
	d.cur = newEpochSink(master, epoch, cfg, false)
	return d
}

// NewRotatingDefragmenter — непрерывный туннель: эпоха следует за wall-clock.
func NewRotatingDefragmenter(master []byte, cfg GeomConfig, T uint64, now time.Time) *Defragmenter {
	ep := EpochFor(now, T)
	d := &Defragmenter{master: master, cfg: cfg.withDefaults(), T: T, epoch: ep,
		cst: true, bySeq: map[uint64][]byte{}, window: 8192, reorderWindow: 64}
	d.cur = newEpochSink(d.master, ep, cfg, true)
	return d
}

// TickEpoch — ротация при смене wall-clock эпохи: текущая уходит в prev
// (продолжает принимать stragglers с границы), новая становится cur.
func (d *Defragmenter) TickEpoch(now time.Time) {
	if d.T == 0 {
		return
	}
	ep := EpochFor(now, d.T)
	if ep != d.epoch {
		d.prev = d.cur
		cfg := d.cfg
		if d.geomFor != nil {
			cfg = d.geomFor(ep).withDefaults()
		}
		d.cur = newEpochSink(d.master, ep, cfg, d.cst)
		d.epoch = ep
	}
}

// Ingest — принять фрагмент с провода. true = опознан и расшифрован.
func (d *Defragmenter) Ingest(wire []byte) bool {
	if len(wire) < cdtNonceLen+cdtSeqLen+16 {
		return false
	}
	nonce := wire[:cdtNonceLen]
	ct := wire[cdtNonceLen:]
	for _, s := range []*epochSink{d.cur, d.prev} {
		if s == nil {
			continue
		}
		s.fill(d.window)
		if _, ok := s.ahead[string(nonce)]; !ok {
			continue
		}
		plain, err := s.aead.Open(nil, nonce, ct, s.aad)
		if err != nil {
			return false // nonce из расписания, но AEAD не сошёлся — чужой/повреждение
		}
		if len(plain) < cdtSeqLen {
			return false
		}
		gseq := binary.BigEndian.Uint64(plain)
		delete(s.ahead, string(nonce))
		s.used++
		d.bySeq[gseq] = plain[cdtSeqLen:]
		d.drain()
		return true
	}
	return false
}

// IngestRaw — расшифровать фрагмент и вернуть его СЫРОЕ сообщение (chunk после
// CDT-seq), БЕЗ потоковой gap-skip сборки. Для надёжного потока (cdtstream),
// который сам управляет streamSeq + retransmit. ok=false — шум/чужой/повреждение.
func (d *Defragmenter) IngestRaw(wire []byte) ([]byte, bool) {
	if len(wire) < cdtNonceLen+cdtSeqLen+16 {
		return nil, false
	}
	nonce := wire[:cdtNonceLen]
	ct := wire[cdtNonceLen:]
	for _, s := range []*epochSink{d.cur, d.prev} {
		if s == nil {
			continue
		}
		s.fill(d.window)
		if _, ok := s.ahead[string(nonce)]; !ok {
			continue
		}
		plain, err := s.aead.Open(nil, nonce, ct, s.aad)
		if err != nil {
			return nil, false
		}
		if len(plain) < cdtSeqLen {
			return nil, false
		}
		delete(s.ahead, string(nonce))
		s.used++
		return plain[cdtSeqLen:], true
	}
	return nil, false
}

func (d *Defragmenter) drain() {
	d.drainContig()
	// gap-skip: потерянный фрагмент не должен останавливать туннель. IP не
	// гарантирует доставку — верхние слои перешлют. Если deliver застрял, а
	// впереди накопились фрагменты дальше окна переупорядочивания, дыра = потеря:
	// скачем через неё (выброшенный кусок = потерянный IP-пакет).
	if len(d.bySeq) == 0 {
		return
	}
	var minS, maxS uint64
	first := true
	for sq := range d.bySeq {
		if first || sq < minS {
			minS = sq
		}
		if first || sq > maxS {
			maxS = sq
		}
		first = false
	}
	if minS > d.deliver && maxS-d.deliver > d.reorderWindow {
		d.deliver = minS
		d.drainContig()
	}
}

func (d *Defragmenter) drainContig() {
	for {
		chunk, ok := d.bySeq[d.deliver]
		if !ok {
			break
		}
		delete(d.bySeq, d.deliver)
		d.ready = append(d.ready, chunk)
		d.deliver++
	}
}

// Next — следующий по глобальному порядку кусок payload.
func (d *Defragmenter) Next() []byte {
	if len(d.ready) == 0 {
		return nil
	}
	c := d.ready[0]
	d.ready = d.ready[1:]
	return c
}

// SetGeomProvider — необязательный провайдер конфигурации эпохи (автопилот
// дисперсии). Провайдер ОБЯЗАН сохранять Dir (ключевая сторона неизменна) и
// выдавать одинаковый конфиг у обеих сторон направления на каждую эпоху,
// иначе приёмник не опознает фрагменты (fail-closed). Консультация — на
// границе эпохи, до создания её геометрии.
func (f *Fragmenter) SetGeomProvider(fn func(epoch uint64) GeomConfig) { f.geomFor = fn }

// SetGeomProvider — см. Fragmenter.SetGeomProvider.
func (d *Defragmenter) SetGeomProvider(fn func(epoch uint64) GeomConfig) { d.geomFor = fn }
