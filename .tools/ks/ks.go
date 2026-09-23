package chaossync

// ks.go — keystream-инверсия ядра chaossync: data-plane на ЛОКАЛЬНОМ
// генераторе keystream из CML-решётки.
//
// Инверсия относительно carrier-режима (session.go/modem.go — НЕ трогаем, он
// остаётся control-plane): там решётка — носитель, идущий по проводу
// (медленно, физика синхронизации). Здесь решётка — генератор ключей на
// ОБЕИХ сторонах локально: по проводу идёт только nonce‖ct. Ключ никогда не
// передаётся.
//
// Модель: для эпохи m обе стороны выводят одно и то же само-валидирующееся
// поле DeriveField и стартовое состояние EpochInit (переиспользованы из
// schedule.go без изменений — гейт Э1 и золотой хэш 29f2315f… сохранены и
// покрывают этот путь). Датаграмма c эпохи m шифруется ключом k_c =
// whiten(state_c), где state_c — c-й шаг решётки от EpochInit. Шагание —
// СТРОГО по счётчику, не по прибытию пакетов: потеря датаграммы не рвёт
// состояние ни на одной из сторон (восстановление позиции — по nonce из
// скользящего окна, см. Receiver).
//
// Wire-формат: headerless UDP-датаграмма nonce‖ct, без номеров/границ.
// AAD = sid эпохи направления (ks-cst-v1 — переиспользование идеи CST из
// cdt_cst.go), выводится локально, на проводе не появляется.
//
// Probe-invisibility: Ingest не прошедшей AEAD датаграммы возвращает
// ok=false, вызывающий молчит — снаружи порт неотличим от фильтрованного.
// Replay: nonce — производная ключа позиции; поглощённый nonce изымается из
// окна (повтор отброшен), граница эпохи — straddle cur/prev (паттерн
// epochSink из CDT-ротации, переиспользован как логика).
//
// Ротация эпох бесплатная: граница по общему счётчику (EpochFor, NTP),
// никакого in-band налога — обе стороны просто шагают дальше.
//
// Этическая граница без изменений: только собственный трафик двух сторон.

import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	ksWhitenLabel = "ks-whiten-v1"
	ksNonceLabel  = "ks-nonce-v1"
	ksCstLabel    = "ks-cst-v1"

	// KsNonceLen — длина nonce на проводе (GCM/ChaCha-Poly1305 размер).
	KsNonceLen = 12
	ksKeyLen   = 32

	// ksWindow — скользящее окно ожидаемых позиций приёмника.
	ksWindow = 8192
)

// Suite — набор bulk-шифра data-plane.
type Suite int

const (
	// SuiteChaCha20Poly1305 — дефолт (быстрый софтверный, переносимый).
	SuiteChaCha20Poly1305 Suite = 0
	// SuiteAEGIS128L — опция под AES-NI. Пока НЕ реализована: честный stub,
	// нужна проверенная реализация AEGIS-128L (в x/crypto её нет), без имитаций.
	SuiteAEGIS128L Suite = 1
)

// ErrSuiteUnsupported — набор шифров заявлен, но не реализован.
var ErrSuiteUnsupported = errors.New("ks: набор шифров не реализован (AEGIS-128L ждёт проверенной реализации)")

// ksAEAD — AEAD под ключ позиции. Дефолт — ChaCha20-Poly1305.
func ksAEAD(suite Suite, key []byte) (cipher.AEAD, error) {
	switch suite {
	case SuiteChaCha20Poly1305:
		return chacha20poly1305.New(key)
	default:
		return nil, ErrSuiteUnsupported
	}
}

// ksCstAAD — AAD датаграммы эпохи: sid направления, усечённый до 16 байт.
// Не передаётся по сети; выводится обеими сторонами локально (идея CST).,
func ksCstAAD(master []byte, epoch uint64, dir string) []byte {
	return epochSeed(master, cdtLabel(ksCstLabel, dir), epoch)[:16]
}

// KeyGen — локальный генератор keystream одного направления одной эпохи.
// Решётка шагает ТОЛЬКО по счётчику; состояние позиции c достижимо
// детерминированным шаганием от EpochInit, без сети.
type KeyGen struct {
	field *FieldParams
	state [Sites]Fxp
	ctr   uint64
}

// NewKeyGen — генератор для (master, epoch, dir). Направления разделены
// через dirMaster: c2n и n2c — независимые генераторы одного ключевого
// семейства.
func NewKeyGen(master []byte, epoch uint64, dir string) *KeyGen {
	m := dirMaster(master, dir)
	return &KeyGen{field: DeriveField(m, epoch), state: EpochInit(m, epoch)}
}

// next — шаг решётки и выдача (key, nonce) очередной позиции.
// whiten: SHA-256(label ‖ ctr ‖ состояние Q16.48); nonce — производная
// ключа (SHA-256 второго label), безопасна к передаче на проводе и служит
// маркером позиции для приёмника. Побитово детерминировано (гейт Э1).
func (k *KeyGen) next() (key [ksKeyLen]byte, nonce [KsNonceLen]byte) {
	k.field.Step(&k.state)
	k.ctr++
	var buf [8 + Sites*8]byte
	binary.BigEndian.PutUint64(buf[:8], k.ctr)
	for i := 0; i < Sites; i++ {
		binary.BigEndian.PutUint64(buf[8+i*8:], uint64(k.state[i].Raw()))
	}
	kh := sha256.New()
	kh.Write([]byte(ksWhitenLabel))
	kh.Write(buf[:])
	copy(key[:], kh.Sum(nil))
	nh := sha256.New()
	nh.Write([]byte(ksNonceLabel))
	nh.Write(key[:])
	copy(nonce[:], nh.Sum(nil))
	return key, nonce
}

// --- передающая сторона ----------------------------------------------------

// Sender — передающая сторона data-plane (одно направление).
type Sender struct {
	master []byte
	dir    string
	suite  Suite
	T      uint64 // сек на эпоху; 0 = фиксированная эпоха (лаборатория)
	epoch  uint64
	kg     *KeyGen
	aad    []byte
}

// NewRotatingSender — боевой режим: эпоха следует за общим счётчиком времени.
func NewRotatingSender(master []byte, dir string, T uint64, now time.Time) *Sender {
	ep := EpochFor(now, T)
	return &Sender{master: master, dir: dir, T: T, epoch: ep,
		kg: NewKeyGen(master, ep, dir), aad: ksCstAAD(master, ep, dir)}
}

// NewSender — фиксированная эпоха (лаборатория/тесты).
func NewSender(master []byte, epoch uint64, dir string) *Sender {
	return &Sender{master: master, dir: dir, epoch: epoch,
		kg: NewKeyGen(master, epoch, dir), aad: ksCstAAD(master, epoch, dir)}
}

// SetSuite — выбор набора шифров (дефолт ChaCha20-Poly1305). Неподдержанный
// набор честно отклоняется.
func (s *Sender) SetSuite(su Suite) error {
	if _, err := ksAEAD(su, make([]byte, ksKeyLen)); err != nil {
		return err
	}
	s.suite = su
	return nil
}

// TickEpoch — ротация по общему счётчику. Бесплатная: просто новый генератор.
func (s *Sender) TickEpoch(now time.Time) {
	if s.T == 0 {
		return
	}
	ep := EpochFor(now, s.T)
	if ep != s.epoch {
		s.epoch = ep
		s.kg = NewKeyGen(s.master, ep, s.dir)
		s.aad = ksCstAAD(s.master, ep, s.dir)
	}
}

// Seal — запечатать датаграмму: wire = nonce‖ct. Шаг решётки — по счётчику,
// независимо от судьбы предыдущих датаграмм.
func (s *Sender) Seal(plain []byte) []byte {
	key, nonce := s.kg.next()
	aead, err := ksAEAD(s.suite, key[:])
	if err != nil {
		panic(err) // недостижимо: набор валидируется в SetSuite/конструкторе
	}
	ct := aead.Seal(nil, nonce[:], plain, s.aad)
	out := make([]byte, 0, KsNonceLen+len(ct))
	out = append(out, nonce[:]...)
	out = append(out, ct...)
	return out
}

// --- принимающая сторона ---------------------------------------------------

// ksEpochSink — контекст одной эпохи: генератор + AAD + окно ожидаемых
// позиций (nonce → key). Логика — как у epochSink CDT-ротации.
type ksEpochSink struct {
	kg    *KeyGen
	aad   []byte
	ahead map[string][ksKeyLen]byte
	gen   uint64
	used  uint64
}

func newKsEpochSink(master []byte, epoch uint64, dir string) *ksEpochSink {
	return &ksEpochSink{
		kg:    NewKeyGen(master, epoch, dir),
		aad:   ksCstAAD(master, epoch, dir),
		ahead: make(map[string][ksKeyLen]byte),
	}
}

// fill — скользящее окно ожидаемых позиций: держим window впереди поглощённых.
func (s *ksEpochSink) fill(window uint64) {
	for s.gen < s.used+window {
		key, nonce := s.kg.next()
		s.ahead[string(nonce[:])] = key
		s.gen++
	}
}

// Receiver — принимающая сторона data-plane. Держит текущую и предыдущую
// эпоху (straddle на границе). Датаграммы независимы: потеря не рвёт
// состояние, переупорядочивание в пределах окна переживается.
type Receiver struct {
	master []byte
	dir    string
	suite  Suite
	T      uint64
	epoch  uint64
	cur    *ksEpochSink
	prev   *ksEpochSink
	window uint64
}

// NewRotatingReceiver — боевой режим: эпоха следует за общим счётчиком.
func NewRotatingReceiver(master []byte, dir string, T uint64, now time.Time) *Receiver {
	ep := EpochFor(now, T)
	return &Receiver{master: master, dir: dir, T: T, epoch: ep,
		cur: newKsEpochSink(master, ep, dir), window: ksWindow}
}

// NewReceiver — фиксированная эпоха (лаборатория/тесты).
func NewReceiver(master []byte, epoch uint64, dir string) *Receiver {
	return &Receiver{master: master, dir: dir, epoch: epoch,
		cur: newKsEpochSink(master, epoch, dir), window: ksWindow}
}

// SetSuite — выбор набора шифров (должен совпадать с отправителем).
func (r *Receiver) SetSuite(su Suite) error {
	if _, err := ksAEAD(su, make([]byte, ksKeyLen)); err != nil {
		return err
	}
	r.suite = su
	return nil
}

// TickEpoch — ротация: текущая эпоха уходит в prev (принимает stragglers),
// новая становится cur.
func (r *Receiver) TickEpoch(now time.Time) {
	if r.T == 0 {
		return
	}
	ep := EpochFor(now, r.T)
	if ep != r.epoch {
		r.prev = r.cur
		r.cur = newKsEpochSink(r.master, ep, r.dir)
		r.epoch = ep
	}
}

// Ingest — принять датаграмму с провода. ok=false → вызывающий МОЛЧИТ
// (probe-invisibility: снаружи порт неотличим от фильтрованного).
func (r *Receiver) Ingest(wire []byte) ([]byte, bool) {
	if len(wire) < KsNonceLen+16 { // nonce + минимальный AEAD-тег
		return nil, false
	}
	nonce := wire[:KsNonceLen]
	ct := wire[KsNonceLen:]
	for _, s := range []*ksEpochSink{r.cur, r.prev} {
		if s == nil {
			continue
		}
		s.fill(r.window)
		key, ok := s.ahead[string(nonce)]
		if !ok {
			continue
		}
		aead, err := ksAEAD(r.suite, key[:])
		if err != nil {
			return nil, false
		}
		plain, err := aead.Open(nil, nonce, ct, s.aad)
		if err != nil {
			return nil, false // nonce из расписания, но AEAD не сошёлся — чужой/повреждение
		}
		delete(s.ahead, string(nonce))
		s.used++
		return plain, true
	}
	return nil, false
}

// --- гейт бит-идентичности -------------------------------------------------

// KsGoldenVector — хэш канонического прогона keystream-ядра: гейт
// бит-идентичности Windows↔Linux для data-plane (пара к SelftestVector Э1).
// Только целочисленная арифметика ядра + SHA-256 → идентичен на любой
// платформе. Расхождение = решётка/whiten дрейфовали, дальше не работаем.
func KsGoldenVector() string {
	h := sha256.New()
	kg := NewKeyGen(SelftestMaster, 424242, "c2n")
	for i := 0; i < 65536; i++ {
		key, nonce := kg.next()
		h.Write(key[:])
		h.Write(nonce[:])
	}
	return hex.EncodeToString(h.Sum(nil))
}
