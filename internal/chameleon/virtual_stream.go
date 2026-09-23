package chameleon

// virtual_stream.go — CST: VirtualStream, логический поток клиента,
// переживающий смерть физического Mux/transport cell.
//
//	SOCKS/TUN -> VirtualStream -> Knowledge Layer -> Mux/cell -> нода -> цель
//
// Пока ячейка жива — дельты текут напрямую. Ячейка умерла — поток НЕ
// закрывается: переходит в DETACHED, записи ограниченно буферизуются в
// replay-окне (дальше лимита — блокировка писателя), KnowledgeLayer
// восстанавливает привязку. Дедлайн восстановления или переполнение памяти
// закрывают поток (EXPIRED/CLOSED) — но никогда не трогают соседние потоки
// и сам Mux.

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// VSState — состояния жизненного цикла VirtualStream.
type VSState uint8

const (
	VSOpening  VSState = iota // CSTOpen отправлен, ждём OpenOK
	VSAttached                // привязан к живому Mux
	VSDetached                // Mux умер, ждём восстановления
	VSResuming                // идёт attach к новой ячейке
	VSClosed                  // закрыт штатно/по ошибке
	VSExpired                 // дедлайн восстановления истёк
)

func (s VSState) String() string {
	switch s {
	case VSOpening:
		return "OPENING"
	case VSAttached:
		return "ATTACHED"
	case VSDetached:
		return "DETACHED"
	case VSResuming:
		return "RESUMING"
	case VSClosed:
		return "CLOSED"
	case VSExpired:
		return "EXPIRED"
	}
	return "?"
}

// Лимиты VirtualStream по умолчанию (клиент).
const (
	vsMaxReplay = 1 << 20 // replay-буфер C2S на поток, байт
	vsMaxInQ    = 1 << 18 // очередь доставленных, но непрочитанных данных
)

var (
	errVSClosed   = errors.New("cst: поток закрыт")
	errVSExpired  = errors.New("cst: поток истёк (восстановление не удалось)")
	errVSOverflow = errors.New("cst: переполнение replay/очереди — поток закрыт")
	errVSNoCST    = errors.New("cst: нода не согласовала CST")
	errVSBadAck   = errors.New("cst: ACK сверх отправленной границы")
	errVSDep      = errors.New("cst: нарушена зависимость дельты")
	errVSDeadline = errors.New("cst: i/o deadline")
)

// replayChunk — неподтверждённый исходящий диапазон.
type replayChunk struct {
	off  uint64
	data []byte
}

// deltaReassembler — строгая последовательная сборка входящих дельт одного
// направления. dependency (dep) для TCP первой версии всегда <= offset:
// дельта принимается только на непрерывной границе; дубли идемпотентны;
// перемешанные ждут зависимости в ограниченном pending-окне.
type deltaReassembler struct {
	boundary   uint64 // следующий ожидаемый offset (== непрерывный конец)
	pending    map[uint64][]byte
	maxPending int
	// delivered — bounded FIFO-журнал уже доставленных сегментов (off -> длина).
	// Нужен, чтобы отличить идемпотентный повтор целого сегмента от
	// противоречивого перекрытия уже собранных данных (overlap-атака).
	delivered    map[uint64]uint64
	deliveredQ   []uint64
	maxDelivered int
}

func newDeltaReassembler() *deltaReassembler {
	return &deltaReassembler{
		pending:      make(map[uint64][]byte),
		maxPending:   8,
		delivered:    make(map[uint64]uint64),
		maxDelivered: 64,
	}
}

// push принимает дельту. Возвращает доставляемые (упорядоченные) payloadы.
// dup=true — дельта-дубликат (идемпотентно пропущена, надо лишь повторить ACK).
func (r *deltaReassembler) push(off, dep uint64, p []byte) (out [][]byte, dup bool, err error) {
	if dep > off {
		return nil, false, errVSDep
	}
	if len(p) == 0 {
		return nil, true, nil // пустая дельта: доставлять нечего
	}
	end := off + uint64(len(p))
	if end <= r.boundary {
		// Ниже непрерывной границы. Идемпотентный дубликат — ТОЛЬКО точный
		// повтор ранее доставленного сегмента (тот же offset и длина). Любое
		// другое перекрытие уже собранных данных — противоречивая пересборка
		// (overlap-атака на реассемблер), протокольная ошибка (fail closed).
		if n, ok := r.delivered[off]; ok && n == uint64(len(p)) {
			return nil, true, nil
		}
		return nil, false, errVSDep
	}
	if off < r.boundary {
		return nil, false, errVSDep // частичное пересечение — протокольная ошибка
	}
	if off > r.boundary {
		if len(r.pending) >= r.maxPending {
			return nil, false, errVSOverflow
		}
		if _, exists := r.pending[off]; !exists {
			r.pending[off] = append([]byte(nil), p...)
		}
		return nil, true, nil // ждёт зависимость; повтор в окне — тоже ок
	}
	// Ровно на границе: доставляем и дренируем pending.
	out = append(out, p)
	r.markDelivered(off, uint64(len(p)))
	r.boundary = end
	for {
		next, ok := r.pending[r.boundary]
		if !ok {
			break
		}
		delete(r.pending, r.boundary)
		out = append(out, next)
		r.markDelivered(r.boundary, uint64(len(next)))
		r.boundary += uint64(len(next))
	}
	return out, false, nil
}

// markDelivered — bounded FIFO-журнал доставленных сегментов: позволяет
// признать повторную доставку идемпотентной, не храня всю историю потока.
// Переполнение вытесняет самую старую запись: очень поздний дубль будет
// отвергнут как errVSDep (fail closed), а не принят вслепую.
func (r *deltaReassembler) markDelivered(off, n uint64) {
	if r.delivered == nil {
		r.delivered = make(map[uint64]uint64)
	}
	if _, ok := r.delivered[off]; ok {
		return
	}
	if r.maxDelivered > 0 && len(r.deliveredQ) >= r.maxDelivered {
		delete(r.delivered, r.deliveredQ[0])
		r.deliveredQ = r.deliveredQ[1:]
	}
	r.delivered[off] = n
	r.deliveredQ = append(r.deliveredQ, off)
}

// dedupWindow — ограниченное окно дедупликации датаграмм (UDP-режим):
// порядок не требуется, повторная доставка внутри окна подавляется.
type dedupWindow struct {
	high uint64
	have bool
	seen map[uint64]bool
	size int
}

func newDedupWindow(size int) *dedupWindow {
	if size < 1 {
		size = 1
	}
	return &dedupWindow{seen: make(map[uint64]bool), size: size}
}

// seenOrAdd: true — датаграмма уже была (или ниже окна) -> дроп.
func (w *dedupWindow) seenOrAdd(id uint64) bool {
	if !w.have {
		w.have, w.high = true, id
		w.seen[id] = true
		return false
	}
	if id > w.high {
		w.high = id
	}
	if w.high >= uint64(w.size) && id < w.high-uint64(w.size) {
		return true // ниже окна — дубликат/устаревшая
	}
	if w.seen[id] {
		return true
	}
	w.seen[id] = true
	for k := range w.seen { // ограничение памяти окна
		if w.high >= uint64(w.size) && k < w.high-uint64(w.size) {
			delete(w.seen, k)
		}
	}
	return false
}

// attachResult — результат attach от ноды (для attachCh).
type attachResult struct {
	nodeC2S     uint64
	nodeS2CNext uint64
	err         error
}

// VirtualStream — логический поток клиента поверх сменяемых Mux-ячеек.
// Реализует net.Conn-подобный интерфейс. Потокобезопасен; активный writer
// всегда один (writeMu).
type VirtualStream struct {
	id     FlowID
	fc     *FlowContinuity
	kl     *KnowledgeLayer
	target string // каноническая цель (входит в continuity key)
	mode   uint8

	writeMu sync.Mutex // единственный активный writer

	mu             sync.Mutex
	state          VSState
	gen            uint32
	sendOff        uint64 // сколько байт приложение записало
	sendAcked      uint64 // knowledge boundary ноды (peer boundary)
	replay         []replayChunk
	replayBytes    int64
	maxReplay      int64
	recv           *deltaReassembler
	dedup          *dedupWindow // UDP
	inQ            [][]byte     // доставлено, ждёт Read
	inQBytes       int64
	recvBoundary   uint64 // доставлено потребителю == acked S2C
	udpSeq         uint64 // исходящий счётчик датаграмм (UDP)
	readDeadline   time.Time
	writeDeadline  time.Time
	detachDeadline time.Time
	finRecv        bool
	dataCh         chan struct{}
	spaceCh        chan struct{}
	dead           chan struct{}
	deadOnce       sync.Once
	sendOnce       sync.Once
	openCh         chan error        // OPENING -> результат
	attachCh       chan attachResult // RESUMING -> результат
}

func newVirtualStream(kl *KnowledgeLayer, id FlowID, fc *FlowContinuity, target string, mode uint8) *VirtualStream {
	return &VirtualStream{
		id: id, fc: fc, kl: kl, target: target, mode: mode,
		state: VSOpening, gen: 1, maxReplay: vsMaxReplay,
		recv: newDeltaReassembler(), dedup: newDedupWindow(256),
		dataCh: make(chan struct{}, 1), spaceCh: make(chan struct{}, 1),
		dead:   make(chan struct{}),
		openCh: make(chan error, 1), attachCh: make(chan attachResult, 1),
	}
}

// ID — стабильный FlowID потока.
func (vs *VirtualStream) ID() FlowID { return vs.id }

// State — текущее состояние (для панели/тестов).
func (vs *VirtualStream) State() VSState {
	vs.mu.Lock()
	defer vs.mu.Unlock()
	return vs.state
}

// Offsets — send/recv границы (для тестов и диагностики).
func (vs *VirtualStream) Offsets() (send, sendAcked, recv uint64) {
	vs.mu.Lock()
	defer vs.mu.Unlock()
	return vs.sendOff, vs.sendAcked, vs.recvBoundary
}

func vsSignal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// finalize — идемпотентный переход в конечное состояние: будит всех
// ждущих, удаляет поток из KnowledgeLayer, затирает ключи. notify=true —
// шлём CSTClose ноде ровно один раз (sendOnce).
func (vs *VirtualStream) finalize(st VSState, notify bool) {
	vs.mu.Lock()
	if vs.state == VSClosed || vs.state == VSExpired {
		vs.mu.Unlock()
		return
	}
	vs.state = st
	vs.mu.Unlock()
	if notify {
		vs.sendOnce.Do(func() { vs.kl.sendClose(vs) })
	}
	vs.kl.removeFlow(vs.id)
	select {
	case vs.openCh <- errVSClosed:
	default:
	}
	select {
	case vs.attachCh <- attachResult{err: errVSClosed}:
	default:
	}
	vs.deadOnce.Do(func() { close(vs.dead) })
	vsSignal(vs.dataCh)
	vsSignal(vs.spaceCh)
	vs.fc.Zeroize()
}

// Close — локальное закрытие потока (нода получает CSTClose, если ячейка жива).
func (vs *VirtualStream) Close() error {
	vs.finalize(VSClosed, true)
	return nil
}

// expire — дедлайн восстановления истёк: поток умирает без уведомления
// (ячейка мертва, нода подчистит свой detached TTL).
func (vs *VirtualStream) expire() { vs.finalize(VSExpired, false) }

// detach — ячейка умерла: поток НЕ закрывается, переходит в DETACHED,
// запускается дедлайн восстановления.
func (vs *VirtualStream) detach() {
	vs.mu.Lock()
	if vs.state == VSAttached || vs.state == VSResuming || vs.state == VSOpening {
		vs.state = VSDetached
		vs.detachDeadline = time.Now().Add(vs.kl.restoreTimeout)
	}
	vs.mu.Unlock()
	vsSignal(vs.dataCh)
	vsSignal(vs.spaceCh)
}

// Read читает доставленные по порядку данные. Каждый прочитанный потребителем
// байт двигает knowledge boundary — ACK уходит ноде только ПОСЛЕ отдачи байтов
// читателю (для TCP; UDP-датаграммы не подтверждаются).
func (vs *VirtualStream) Read(p []byte) (int, error) {
	for {
		vs.mu.Lock()
		if len(vs.inQ) > 0 {
			chunk := vs.inQ[0]
			n := copy(p, chunk)
			if n < len(chunk) {
				vs.inQ[0] = chunk[n:]
			} else {
				vs.inQ[0] = nil
				vs.inQ = vs.inQ[1:]
				if len(vs.inQ) == 0 {
					vs.inQ = nil
				}
			}
			vs.inQBytes -= int64(n)
			vs.recvBoundary += uint64(n)
			ack := vs.recvBoundary
			st := vs.state
			vs.mu.Unlock()
			if st == VSAttached && vs.mode == CSTModeTCP {
				vs.kl.sendAck(vs, ack)
			}
			return n, nil
		}
		if vs.finRecv {
			vs.mu.Unlock()
			return 0, io.EOF
		}
		switch vs.state {
		case VSClosed:
			vs.mu.Unlock()
			return 0, errVSClosed
		case VSExpired:
			vs.mu.Unlock()
			return 0, errVSExpired
		}
		// Дедлайн восстановления действует и на заблокированное чтение.
		st2 := vs.state
		if (st2 == VSDetached || st2 == VSResuming) && !vs.detachDeadline.IsZero() && time.Now().After(vs.detachDeadline) {
			vs.mu.Unlock()
			vs.expire()
			return 0, errVSExpired
		}
		dl := vs.readDeadline
		vs.mu.Unlock()
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return 0, errVSDeadline
			}
			t := time.NewTimer(d)
			select {
			case <-vs.dataCh:
				t.Stop()
			case <-vs.dead:
				t.Stop()
			case <-t.C:
				return 0, errVSDeadline
			}
		} else {
			select {
			case <-vs.dataCh:
			case <-vs.dead:
			}
		}
	}
}

// Write пишет в логический поток: байты сегментируются в дельты, попадают в
// bounded replay-буфер (освобождается ТОЛЬКО по knowledge ACK ноды) и, если
// ячейка жива, отправляются. В DETACHED запись буферизуется в то же окно;
// переполнение блокирует writer до ACK/attach, дедлайна или закрытия.
func (vs *VirtualStream) Write(p []byte) (int, error) {
	if vs.mode == CSTModeUDP {
		return vs.writeDatagram(p)
	}
	vs.writeMu.Lock()
	defer vs.writeMu.Unlock()
	total := 0
	for total < len(p) {
		n := min(len(p)-total, maxCSTPayload)
		for {
			vs.mu.Lock()
			st := vs.state
			if st == VSClosed {
				vs.mu.Unlock()
				return total, errVSClosed
			}
			if st == VSExpired {
				vs.mu.Unlock()
				return total, errVSExpired
			}
			if (st == VSDetached || st == VSResuming) && !vs.detachDeadline.IsZero() && time.Now().After(vs.detachDeadline) {
				vs.mu.Unlock()
				vs.expire()
				return total, errVSExpired
			}
			if vs.replayBytes+int64(n) <= vs.maxReplay {
				off := vs.sendOff
				chunk := append([]byte(nil), p[total:total+n]...)
				vs.replay = append(vs.replay, replayChunk{off: off, data: chunk})
				vs.replayBytes += int64(n)
				vs.sendOff += uint64(n)
				vs.mu.Unlock()
				if st == VSAttached {
					vs.kl.sendDelta(vs, off, chunk, 0, 0)
				}
				break
			}
			dl := vs.writeDeadline
			det := vs.detachDeadline
			detached := st == VSDetached || st == VSResuming || st == VSOpening
			vs.mu.Unlock()
			if detached && !det.IsZero() && time.Now().After(det) {
				vs.expire()
				return total, errVSExpired
			}
			if !dl.IsZero() && time.Now().After(dl) {
				return total, errVSDeadline
			}
			select {
			case <-vs.spaceCh:
			case <-vs.dead:
				return total, errVSClosed
			case <-time.After(25 * time.Millisecond):
			}
		}
		total += n
	}
	return total, nil
}

// writeDatagram — UDP-режим: каждая датаграмма — независимая дельта с
// собственным идентификатором, без replay (UDP терпит потери; expired и
// дубли подавляются на приёмной стороне). Вне ATTACHED — молчимый дроп,
// эквивалентный потере пакета.
func (vs *VirtualStream) writeDatagram(p []byte) (int, error) {
	if len(p) > maxCSTDatagram {
		return 0, errors.New("cst: датаграмма сверх лимита")
	}
	vs.mu.Lock()
	st := vs.state
	if st == VSClosed || st == VSExpired {
		vs.mu.Unlock()
		return 0, errVSClosed
	}
	seq := vs.udpSeq
	vs.udpSeq++
	vs.mu.Unlock()
	if st != VSAttached {
		return len(p), nil
	}
	vs.kl.sendDelta(vs, seq, p, CSTFlagDatagram, time.Now().Add(10*time.Second).UnixMilli())
	return len(p), nil
}

// onDelta — входящая S2C-дельта из цикла mux (горячий путь: без блокировок).
func (vs *VirtualStream) onDelta(d *CSTDelta) {
	vs.mu.Lock()
	st := vs.state
	if st == VSClosed || st == VSExpired {
		vs.mu.Unlock()
		return
	}
	if d.Gen != vs.gen || d.Dir != CSTDirS2C {
		vs.mu.Unlock()
		return // чужое поколение/направление — молча
	}
	if !d.VerifyTag(vs.fc) {
		vs.mu.Unlock()
		go vs.finalize(VSClosed, false) // протокольная ошибка — только поток
		return
	}
	if d.Expired(time.Now().UnixMilli()) {
		vs.mu.Unlock()
		return // expired не воспроизводятся
	}
	if vs.mode == CSTModeUDP {
		if vs.dedup.seenOrAdd(d.Offset) {
			vs.mu.Unlock()
			return
		}
		if vs.inQBytes+int64(len(d.Payload)) > vsMaxInQ {
			vs.mu.Unlock()
			go vs.finalize(VSClosed, false)
			return
		}
		vs.inQ = append(vs.inQ, d.Payload)
		vs.inQBytes += int64(len(d.Payload))
		vs.mu.Unlock()
		vsSignal(vs.dataCh)
		return
	}
	out, dup, err := vs.recv.push(d.Offset, d.Dep, d.Payload)
	if err != nil {
		vs.mu.Unlock()
		go vs.finalize(VSClosed, false)
		return
	}
	if dup {
		ack := vs.recvBoundary
		vs.mu.Unlock()
		vs.kl.sendAck(vs, ack) // повторный ACK идемпотентен
		return
	}
	for _, c := range out {
		vs.inQ = append(vs.inQ, c)
		vs.inQBytes += int64(len(c))
	}
	overflow := vs.inQBytes > vsMaxInQ
	if d.Flags&CSTFlagFIN != 0 {
		vs.finRecv = true
	}
	vs.mu.Unlock()
	if overflow {
		vs.finalize(VSClosed, false) // медленный потребитель: закрываем ТОЛЬКО поток
		return
	}
	vsSignal(vs.dataCh)
}

// onAck — knowledge ACK от ноды по направлению C2S: монотонен, идемпотентен,
// освобождает replay-буфер. ACK сверх отправленной границы закрывает поток.
func (vs *VirtualStream) onAck(a *CSTAck) {
	vs.mu.Lock()
	st := vs.state
	if st == VSClosed || st == VSExpired {
		vs.mu.Unlock()
		return
	}
	if a.Gen != vs.gen || a.Dir != CSTDirC2S || !a.VerifyTag(vs.fc) {
		vs.mu.Unlock()
		return
	}
	if a.Ack > vs.sendOff {
		vs.mu.Unlock()
		vs.finalize(VSClosed, false)
		return
	}
	if a.Ack <= vs.sendAcked {
		vs.mu.Unlock()
		return
	}
	vs.trimLocked(a.Ack)
	vs.mu.Unlock()
	vsSignal(vs.spaceCh)
}

// trimLocked освобождает replay ниже границы ack (вызывается под vs.mu).
func (vs *VirtualStream) trimLocked(ack uint64) {
	vs.sendAcked = ack
	for len(vs.replay) > 0 {
		head := vs.replay[0]
		headEnd := head.off + uint64(len(head.data))
		if headEnd <= ack {
			vs.replayBytes -= int64(len(head.data))
			vs.replay[0] = replayChunk{}
			vs.replay = vs.replay[1:]
			continue
		}
		if head.off < ack {
			trim := ack - head.off
			vs.replay[0] = replayChunk{off: ack, data: head.data[trim:]}
			vs.replayBytes -= int64(trim)
		}
		break
	}
	if len(vs.replay) == 0 {
		vs.replay = nil
	}
}

// onPeerClose — нода закрыла поток (egress умер, policy, лимиты, expiry).
func (vs *VirtualStream) onPeerClose(reason uint8) {
	vs.finalize(VSClosed, false)
}

// onSnapshot — snapshot от ноды: подтверждённые границы, подрезка replay.
func (vs *VirtualStream) onSnapshot(s *CSTSnapshot) {
	vs.mu.Lock()
	defer vs.mu.Unlock()
	if vs.state == VSClosed || vs.state == VSExpired {
		return
	}
	if s.Gen != vs.gen || !s.VerifyMAC(vs.fc) {
		return
	}
	if s.C2SAcked > vs.sendAcked && s.C2SAcked <= vs.sendOff {
		vs.trimLocked(s.C2SAcked)
	}
}

// --- net.Conn-интерфейс ---

func (vs *VirtualStream) SetDeadline(t time.Time) error {
	vs.mu.Lock()
	vs.readDeadline, vs.writeDeadline = t, t
	vs.mu.Unlock()
	return nil
}

func (vs *VirtualStream) SetReadDeadline(t time.Time) error {
	vs.mu.Lock()
	vs.readDeadline = t
	vs.mu.Unlock()
	return nil
}

func (vs *VirtualStream) SetWriteDeadline(t time.Time) error {
	vs.mu.Lock()
	vs.writeDeadline = t
	vs.mu.Unlock()
	return nil
}

type vsAddr string

func (a vsAddr) Network() string { return "cst" }
func (a vsAddr) String() string  { return string(a) }

// LocalAddr / RemoteAddr — символические адреса логического потока.
func (vs *VirtualStream) LocalAddr() net.Addr  { return vsAddr("cst-local") }
func (vs *VirtualStream) RemoteAddr() net.Addr { return vsAddr(vs.target) }
