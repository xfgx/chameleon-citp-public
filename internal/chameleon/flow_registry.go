package chameleon

// flow_registry.go — CST: FlowRegistry ноды. Общий реестр логических потоков,
// НЕЗАВИСИМЫЙ от отдельного Mux: FlowID -> FlowState. Именно здесь переживает
// смерть клиентской ячейки соединение нода->цель (egress), offsets обоих
// направлений, replay-окна и continuity-ключи.
//
// Жёсткие лимиты (state-exhaustion DoS): потоков на клиента/всего, detached,
// replay-байт на поток/клиента/глобально, TTL detached и манифеста, bounded
// pending-дельты, LRU-вытеснение detached, уборка в отдельном цикле,
// идемпотентный Shutdown. При исчерпании лимитов — fail closed: поток
// закрывается, никакого незащищённого прямого пути не появляется.
//
// Порядок блокировок (не нарушать): registry.mu -> flow.mu -> mux send.

import (
	"container/list"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// FlowLimits — обязательные лимиты реестра.
type FlowLimits struct {
	MaxFlowsPerClient       int
	MaxFlowsTotal           int
	MaxDetached             int
	MaxReplayBytesPerFlow   int64
	MaxReplayBytesPerClient int64
	MaxReplayBytesTotal     int64
	DetachedTTL             time.Duration
	ManifestTTL             time.Duration
	IdleTTL                 time.Duration
	MaxPendingPerFlow       int
	SweepInterval           time.Duration
}

// DefaultFlowLimits — безопасные значения по умолчанию.
func DefaultFlowLimits() FlowLimits {
	return FlowLimits{
		MaxFlowsPerClient:       64,
		MaxFlowsTotal:           1024,
		MaxDetached:             256,
		MaxReplayBytesPerFlow:   1 << 20,
		MaxReplayBytesPerClient: 4 << 20,
		MaxReplayBytesTotal:     32 << 20,
		DetachedTTL:             120 * time.Second,
		ManifestTTL:             30 * time.Second,
		IdleTTL:                 30 * time.Minute,
		MaxPendingPerFlow:       8,
		SweepInterval:           5 * time.Second,
	}
}

// cstIngress — единица входящей очереди C2S (запись в egress).
type cstIngress struct {
	data []byte
	fin  bool
}

// FlowState — состояние одного логического потока на ноде.
type FlowState struct {
	id       FlowID
	client   [32]byte // авторизованный клиент (публичный ключ из handshake)
	target   string   // каноническая цель host:port (менять при attach НЕЛЬЗЯ)
	tkey     string   // ключ цели в continuity key (с префиксом режима)
	mode     uint8
	fc       *FlowContinuity
	secret   []byte // FlowSecret: живёт только здесь, затирается при закрытии
	reg      *FlowRegistry
	chainUDP bool // egress — поток каскада (u16-кадрировка датаграмм)

	mu          sync.Mutex
	gen         uint32
	c2sBoundary uint64 // клиент->цель: байт записано в egress
	c2sPending  map[uint64]*CSTDelta
	s2cNext     uint64 // цель->клиент: следующий offset отправки
	s2cAcked    uint64 // ...подтверждено клиентом
	s2cReplay   []replayChunk
	replayBytes int64
	egress      net.Conn // соединение нода->цель; живёт вне Mux
	dedupC2S    *dedupWindow
	c2sQ        chan cstIngress
	attached    bool
	attachedTo  *Mux
	closing     bool
	lastActive  time.Time
	detachedAt  time.Time
	expiryMs    int64
	done        chan struct{}
	closeOnce   sync.Once
	spaceCh     chan struct{}
	lruElem     *list.Element // под r.mu
}

// FlowRegistry — общий bounded реестр потоков ноды.
type FlowRegistry struct {
	mu          sync.Mutex
	flows       map[FlowID]*FlowState
	byClient    map[[32]byte]map[FlowID]struct{}
	replayTotal int64
	lru         *list.List // detached-потоки, back = старейший
	limits      FlowLimits
	nodePub     []byte
	stopCh      chan struct{}
	once        sync.Once
	wg          sync.WaitGroup
}

func NewFlowRegistry(l FlowLimits, nodePub []byte) *FlowRegistry {
	r := &FlowRegistry{
		flows:    make(map[FlowID]*FlowState),
		byClient: make(map[[32]byte]map[FlowID]struct{}),
		lru:      list.New(),
		limits:   l,
		nodePub:  append([]byte(nil), nodePub...),
		stopCh:   make(chan struct{}),
	}
	if r.limits.SweepInterval <= 0 {
		r.limits.SweepInterval = 5 * time.Second
	}
	r.wg.Add(1)
	go r.sweeper()
	return r
}

// Shutdown — идемпотентный: стоп уборщика, закрытие всех потоков и egress.
func (r *FlowRegistry) Shutdown() {
	r.once.Do(func() {
		close(r.stopCh)
		r.mu.Lock()
		var all []*FlowState
		for _, f := range r.flows {
			all = append(all, f)
		}
		r.mu.Unlock()
		for _, f := range all {
			r.closeFlow(f, CSTCloseNormal, false)
		}
		// r.wg считает не только уборщика, но и насосы каждого потока
		// (writerLoop/pumpLoop, wg.Add(2) в openFlow). Насосы выходят лишь
		// после close(f.done) и egress.Close() внутри closeFlow, поэтому
		// ждать ДО закрытия потоков нельзя — это взаимная блокировка.
		r.wg.Wait() // уборщик + насосы потоков
	})
}

// Stats — диагностика реестра (для журнала/тестов).
func (r *FlowRegistry) Stats() (flows, detached int, replayBytes int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.flows), r.lru.Len(), r.replayTotal
}

// flowInfo — offsets потока (для тестов).
func (r *FlowRegistry) flowInfo(id FlowID) (gen uint32, c2s, s2cNext, s2cAcked uint64, attached bool, ok bool) {
	r.mu.Lock()
	f := r.flows[id]
	r.mu.Unlock()
	if f == nil {
		return 0, 0, 0, 0, false, false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gen, f.c2sBoundary, f.s2cNext, f.s2cAcked, f.attached, true
}

// closeFlow — идемпотентное закрытие потока на ноде: вынос из реестра,
// закрытие egress, затирание FlowSecret/CK. notify=true — CSTClose клиенту
// (кадр кодируется ДО затирания ключей). Сетевой вызов — вне блокировок.
func (r *FlowRegistry) closeFlow(f *FlowState, reason uint8, notify bool) {
	f.closeOnce.Do(func() {
		r.mu.Lock()
		if _, ok := r.flows[f.id]; ok {
			delete(r.flows, f.id)
			if set := r.byClient[f.client]; set != nil {
				delete(set, f.id)
				if len(set) == 0 {
					delete(r.byClient, f.client)
				}
			}
			f.mu.Lock()
			r.replayTotal -= f.replayBytes
			f.mu.Unlock()
		}
		if f.lruElem != nil {
			r.lru.Remove(f.lruElem)
			f.lruElem = nil
		}
		r.mu.Unlock()
		f.mu.Lock()
		f.closing = true
		notifyTo := f.attachedTo
		wasAttached := f.attached
		f.attached = false
		f.attachedTo = nil
		f.mu.Unlock()
		var frame []byte
		if notify && wasAttached && notifyTo != nil {
			c := &CSTClose{Version: 1, ID: f.id, Reason: reason}
			frame = c.Encode(f.fc)
		}
		close(f.done)
		if f.egress != nil {
			_ = f.egress.Close()
		}
		ZeroizeBytes(f.secret)
		f.fc.Zeroize()
		if frame != nil && notifyTo.Alive() {
			_ = notifyTo.send(0, smCSTClose, frame)
		}
	})
}

// sweeper — отдельный безопасный цикл очистки: TTL detached/idle/expiry и
// глобальный лимит памяти (LRU-вытеснение detached, fail closed).
func (r *FlowRegistry) sweeper() {
	defer r.wg.Done()
	t := time.NewTicker(r.limits.SweepInterval)
	defer t.Stop()
	for {
		select {
		case <-r.stopCh:
			return
		case now := <-t.C:
			r.sweep(now)
		}
	}
}

func (r *FlowRegistry) sweep(now time.Time) {
	var closeList []*FlowState
	var reasons []uint8
	r.mu.Lock()
	nowMs := now.UnixMilli()
	for _, f := range r.flows {
		f.mu.Lock()
		switch {
		case !f.attached && !f.detachedAt.IsZero() && now.Sub(f.detachedAt) > r.limits.DetachedTTL:
			closeList = append(closeList, f)
			reasons = append(reasons, CSTCloseExpired)
		case now.Sub(f.lastActive) > r.limits.IdleTTL:
			closeList = append(closeList, f)
			reasons = append(reasons, CSTCloseExpired)
		case f.expiryMs > 0 && nowMs > f.expiryMs:
			closeList = append(closeList, f)
			reasons = append(reasons, CSTCloseExpired)
		}
		f.mu.Unlock()
	}
	for r.replayTotal > r.limits.MaxReplayBytesTotal && r.lru.Len() > 0 {
		e := r.lru.Back()
		f, _ := e.Value.(*FlowState)
		r.lru.Remove(e)
		if f != nil {
			f.lruElem = nil
			closeList = append(closeList, f)
			reasons = append(reasons, CSTCloseLimits)
		}
	}
	r.mu.Unlock()
	for i, f := range closeList {
		r.closeFlow(f, reasons[i], true)
	}
}

// addReplay — глобальный учёт replay-памяти и per-client лимит (fail closed).
func (r *FlowRegistry) addReplay(f *FlowState, n int64) {
	r.mu.Lock()
	r.replayTotal += n
	var sum int64
	for id := range r.byClient[f.client] {
		if of := r.flows[id]; of != nil {
			of.mu.Lock()
			sum += of.replayBytes
			of.mu.Unlock()
		}
	}
	over := sum > r.limits.MaxReplayBytesPerClient
	r.mu.Unlock()
	if over {
		r.closeFlow(f, CSTCloseLimits, true)
	}
}

// subReplay — освобождение глобального учёта после ACK/snapshot.
func (r *FlowRegistry) subReplay(n int64) {
	if n <= 0 {
		return
	}
	r.mu.Lock()
	r.replayTotal -= n
	if r.replayTotal < 0 {
		r.replayTotal = 0
	}
	r.mu.Unlock()
}

// CSTServerConfig — привязка CST к серверной стороне Mux.
type CSTServerConfig struct {
	Registry  *FlowRegistry
	NodePub   []byte // публичный ключ ноды (входит в continuity key)
	ClientPub []byte // публичный ключ клиента ЭТОГО сеанса (из handshake)
}

// serverHandlers — набор обработчиков CST-кадров ноды. Open/Attach идут через
// bounded dispatch мультиплексора (дозвон может блокироваться); delta/ack —
// инлайн и неблокирующие (очередь потока ограничена, переполнение закрывает
// ТОЛЬКО поток).
func (r *FlowRegistry) serverHandlers(m *Mux, cfg *CSTServerConfig, dialTimeout time.Duration) *cstHandlers {
	return &cstHandlers{
		onHello: func(mx *Mux, p []byte) {
			h, err := DecodeCSTHello(p)
			if err != nil || h.Flags&CSTFlagSupported == 0 {
				return
			}
			_ = mx.send(0, smCSTCap, (&CSTHello{Version: CSTVersion, Flags: CSTFlagSupported}).Encode())
		},
		onOpen:     func(mx *Mux, p []byte) { r.handleOpen(mx, cfg, p, dialTimeout) },
		onDelta:    func(mx *Mux, p []byte) { r.handleDelta(mx, p) },
		onAck:      func(mx *Mux, p []byte) { r.handleAck(mx, p) },
		onAttach:   func(mx *Mux, p []byte) { r.handleAttach(mx, cfg, p) },
		onDetach:   func(mx *Mux, p []byte) { r.handleDetach(mx, p) },
		onSnapshot: func(mx *Mux, p []byte) { r.handleSnapshot(mx, p) },
		onClose:    func(mx *Mux, p []byte) { r.handleClose(mx, p) },
	}
}

// handleOpen — KnowledgeOpen: строгий разбор, DNS-binding (RO), единая
// server policy, лимиты, дозвон к цели ВНЕ блокировок реестра.
func (r *FlowRegistry) handleOpen(m *Mux, cfg *CSTServerConfig, p []byte, dialTimeout time.Duration) {
	replyErr := func(id FlowID, msg string) {
		_ = m.send(0, smCSTOpenErr, (&CSTErr{Version: CSTVersion, ID: id, Msg: msg}).Encode())
	}
	o, err := DecodeCSTOpen(p)
	if err != nil {
		replyErr(FlowID{}, "bad open")
		return
	}
	if o.Version != CSTVersion {
		replyErr(o.ID, "unsupported version")
		return
	}
	var target string
	if o.Mode == CSTModeUDP {
		if len(o.Target) < 2 || o.Target[0] != udpTargetMarker {
			replyErr(o.ID, "udp: bad target")
			return
		}
		target = string(o.Target[1:])
	} else {
		t, perr := ParseTarget(o.Target)
		if perr != nil {
			replyErr(o.ID, "bad target")
			return
		}
		target = t
	}
	if len(o.RO) > 0 { // DNS-binding: цель обязана быть из подписанного набора
		ro, rerr := DecodeResolutionObject(o.RO)
		if rerr != nil || ro.Verify(m.conn.seed) != nil {
			replyErr(o.ID, "bad resolution object")
			return
		}
		host, _, serr := net.SplitHostPort(target)
		if serr != nil || !ro.MatchHost(host) {
			replyErr(o.ID, "target not in resolution")
			return
		}
	}
	if err := m.authorizeOpen(target); err != nil { // та же policy, что у legacy
		replyErr(o.ID, "policy")
		return
	}
	var client [32]byte
	copy(client[:], cfg.ClientPub)
	f, err := r.openFlow(cfg, o, client, target, m, dialTimeout)
	if err != nil {
		replyErr(o.ID, err.Error())
		return
	}
	_ = m.send(0, smCSTOpenOK, (&CSTOpenOK{Version: CSTVersion, ID: f.id, Gen: f.gen}).Encode())
}

// openFlow — лимиты (fail closed), дозвон (egress-каскад или direct),
// регистрация, запуск насосов. Дозвон — вне registry lock.
func (r *FlowRegistry) openFlow(cfg *CSTServerConfig, o *CSTOpen, client [32]byte, target string, m *Mux, dialTimeout time.Duration) (*FlowState, error) {
	r.mu.Lock()
	if len(r.flows) >= r.limits.MaxFlowsTotal || len(r.byClient[client]) >= r.limits.MaxFlowsPerClient {
		r.mu.Unlock()
		return nil, errors.New("limits: потоков сверх лимита")
	}
	r.mu.Unlock()
	var egress net.Conn
	var err error
	chainUDP := false
	if o.Mode == CSTModeUDP {
		if m.egressUDP != nil {
			egress, err = m.egressUDP(target)
			chainUDP = true
		} else {
			egress, err = net.DialTimeout("udp", target, dialTimeout)
		}
	} else if m.egress != nil {
		egress, err = m.egress(target) // каскад: fail-closed внутри UpstreamChain
	} else {
		egress, err = net.DialTimeout("tcp", target, dialTimeout)
	}
	if err != nil {
		return nil, errors.New("dial failed")
	}
	if tc, ok := egress.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	tkey := cstTargetKey(o.Mode, target)
	f := &FlowState{
		id: o.ID, client: client, target: target, tkey: tkey,
		mode: o.Mode, fc: DeriveContinuity(o.Secret[:], cfg.ClientPub, cfg.NodePub, o.ID, tkey),
		secret: append([]byte(nil), o.Secret[:]...), reg: r, chainUDP: chainUDP,
		gen: 1, c2sPending: make(map[uint64]*CSTDelta), dedupC2S: newDedupWindow(256),
		egress: egress, c2sQ: make(chan cstIngress, 32),
		attached: true, attachedTo: m, lastActive: time.Now(),
		done: make(chan struct{}), spaceCh: make(chan struct{}, 1),
	}
	r.mu.Lock()
	if len(r.flows) >= r.limits.MaxFlowsTotal || len(r.byClient[client]) >= r.limits.MaxFlowsPerClient {
		r.mu.Unlock()
		_ = egress.Close()
		return nil, errors.New("limits: лимит при дозвоне")
	}
	r.flows[f.id] = f
	set := r.byClient[client]
	if set == nil {
		set = make(map[FlowID]struct{})
		r.byClient[client] = set
	}
	set[f.id] = struct{}{}
	r.mu.Unlock()
	r.wg.Add(2)
	go f.writerLoop()
	go f.pumpLoop()
	return f, nil
}

// handleDelta — входящая C2S-дельта (инлайн из цикла mux: БЕЗ блокировок).
// Проверки: поток известен, ячейка == привязанной, поколение совпадает,
// HMAC, expiry. Дубликат -> повторный ACK (идемпотентно). Перемешанные —
// bounded pending до зависимости. Переполнение очереди — закрытие ТОЛЬКО
// этого потока, глобальный Mux не блокируется никогда.
func (r *FlowRegistry) handleDelta(m *Mux, p []byte) {
	d, err := DecodeCSTDelta(p)
	if err != nil {
		return
	}
	r.mu.Lock()
	f := r.flows[d.ID]
	r.mu.Unlock()
	if f == nil {
		return
	}
	f.mu.Lock()
	if f.closing || !f.attached || f.attachedTo != m || d.Gen != f.gen {
		f.mu.Unlock()
		return // старый Mux/старое поколение писать не может
	}
	if !d.VerifyTag(f.fc) {
		f.mu.Unlock()
		go r.closeFlow(f, CSTCloseProtocolError, true)
		return
	}
	if d.Dir != CSTDirC2S || d.Expired(time.Now().UnixMilli()) {
		f.mu.Unlock()
		return
	}
	f.lastActive = time.Now()
	if f.mode == CSTModeUDP {
		if f.dedupC2S.seenOrAdd(d.Offset) || len(d.Payload) > maxCSTDatagram {
			f.mu.Unlock()
			return
		}
		select {
		case f.c2sQ <- cstIngress{data: d.Payload}:
			f.mu.Unlock()
		default:
			f.mu.Unlock()
			go r.closeFlow(f, CSTCloseLimits, true)
		}
		return
	}
	if d.Dep > d.Offset {
		f.mu.Unlock()
		go r.closeFlow(f, CSTCloseProtocolError, true)
		return
	}
	end := d.Offset + uint64(len(d.Payload))
	switch {
	case end <= f.c2sBoundary:
		boundary := f.c2sBoundary
		f.mu.Unlock()
		f.sendAckTo(boundary) // дубликат: повторный ACK, данных в egress нет
	case d.Offset == f.c2sBoundary:
		select {
		case f.c2sQ <- cstIngress{data: d.Payload, fin: d.Flags&CSTFlagFIN != 0}:
			f.mu.Unlock()
		default:
			f.mu.Unlock()
			go r.closeFlow(f, CSTCloseLimits, true)
		}
	default:
		if len(f.c2sPending) >= r.limits.MaxPendingPerFlow {
			f.mu.Unlock()
			go r.closeFlow(f, CSTCloseLimits, true)
			return
		}
		if _, ok := f.c2sPending[d.Offset]; !ok {
			f.c2sPending[d.Offset] = d
		}
		f.mu.Unlock()
	}
}

// handleAck — knowledge ACK клиента по S2C: монотонен, идемпотентен,
// освобождает replay ТОЛЬКО по подтверждённой границе. ACK сверх отправленной
// границы — протокольная ошибка: закрывается только этот поток.
func (r *FlowRegistry) handleAck(m *Mux, p []byte) {
	a, err := DecodeCSTAck(p)
	if err != nil {
		return
	}
	r.mu.Lock()
	f := r.flows[a.ID]
	r.mu.Unlock()
	if f == nil {
		return
	}
	f.mu.Lock()
	if f.closing || !f.attached || f.attachedTo != m || a.Gen != f.gen || a.Dir != CSTDirS2C {
		f.mu.Unlock()
		return
	}
	if !a.VerifyTag(f.fc) {
		f.mu.Unlock()
		go r.closeFlow(f, CSTCloseProtocolError, true)
		return
	}
	f.lastActive = time.Now()
	if a.Ack > f.s2cNext {
		f.mu.Unlock()
		go r.closeFlow(f, CSTCloseProtocolError, true)
		return
	}
	if a.Ack <= f.s2cAcked {
		f.mu.Unlock()
		return
	}
	freed := f.trimS2CLocked(a.Ack)
	f.mu.Unlock()
	r.subReplay(freed)
	vsSignal(f.spaceCh)
}

// trimS2CLocked освобождает S2C replay ниже ack (под f.mu). Возвращает
// освобождённые байты для глобального учёта.
func (f *FlowState) trimS2CLocked(ack uint64) int64 {
	f.s2cAcked = ack
	before := f.replayBytes
	for len(f.s2cReplay) > 0 {
		head := f.s2cReplay[0]
		headEnd := head.off + uint64(len(head.data))
		if headEnd <= ack {
			f.replayBytes -= int64(len(head.data))
			f.s2cReplay[0] = replayChunk{}
			f.s2cReplay = f.s2cReplay[1:]
			continue
		}
		if head.off < ack {
			trim := ack - head.off
			f.s2cReplay[0] = replayChunk{off: ack, data: head.data[trim:]}
			f.replayBytes -= int64(trim)
		}
		break
	}
	if len(f.s2cReplay) == 0 {
		f.s2cReplay = nil
	}
	return before - f.replayBytes
}

// handleAttach — Manifest/Attach: присоединение detached-потока к НОВОЙ
// физической сессии. Отклоняются: неизвестный поток, чужой клиент, истёкший
// манифест (TTL), replay старого манифеста (MAC привязан к seed НОВОЙ
// сессии), generation rollback, граница клиента в будущем, повторный attach
// при живой привязке (выигрывает только одна сессия). Target и policy при
// attach не пересматриваются — они зафиксированы при OPEN.
func (r *FlowRegistry) handleAttach(m *Mux, cfg *CSTServerConfig, p []byte) {
	replyErr := func(id FlowID, msg string) {
		_ = m.send(0, smCSTAttachErr, (&CSTErr{Version: CSTVersion, ID: id, Msg: msg}).Encode())
	}
	at, err := DecodeCSTAttach(p)
	if err != nil {
		replyErr(FlowID{}, "bad attach")
		return
	}
	r.mu.Lock()
	f := r.flows[at.ID]
	r.mu.Unlock()
	if f == nil {
		replyErr(at.ID, cstErrUnknownFlow)
		return
	}
	f.mu.Lock()
	if f.closing {
		f.mu.Unlock()
		replyErr(at.ID, cstErrUnknownFlow)
		return
	}
	var client [32]byte
	copy(client[:], cfg.ClientPub)
	if f.client != client {
		f.mu.Unlock()
		replyErr(at.ID, "foreign client") // attach чужого клиента
		return
	}
	nowMs := time.Now().UnixMilli()
	if at.ExpiryMs > 0 && nowMs > at.ExpiryMs {
		f.mu.Unlock()
		replyErr(at.ID, "manifest expired")
		return
	}
	if !at.VerifyMAC(f.fc, m.conn.seed) {
		f.mu.Unlock()
		replyErr(at.ID, "MAC") // replay старого манифеста / чужая сессия
		return
	}
	if at.NewGen <= f.gen {
		f.mu.Unlock()
		replyErr(at.ID, "generation rollback")
		return
	}
	if f.attached {
		f.mu.Unlock()
		replyErr(at.ID, "already attached") // одна активная ячейка
		return
	}
	if at.ClientS2CAcked > f.s2cNext {
		f.mu.Unlock()
		replyErr(at.ID, "boundary in future")
		return
	}
	// Победитель: привязка к новой ячейке, поколение повышается.
	f.gen = at.NewGen
	f.attached = true
	f.attachedTo = m
	f.detachedAt = time.Time{}
	f.lastActive = time.Now()
	var freed int64
	if at.ClientS2CAcked > f.s2cAcked {
		freed = f.trimS2CLocked(at.ClientS2CAcked)
	}
	tail := append([]replayChunk(nil), f.s2cReplay...)
	ok := &CSTAttachOK{Version: 1, ID: f.id, Gen: f.gen, NodeC2SBoundary: f.c2sBoundary, NodeS2CNext: f.s2cNext}
	enc := ok.Encode(f.fc, m.conn.seed)
	gen := f.gen
	f.mu.Unlock()
	if freed > 0 {
		r.subReplay(freed)
	}
	r.mu.Lock() // вынос из LRU detached (поле под r.mu)
	if f.lruElem != nil {
		r.lru.Remove(f.lruElem)
		f.lruElem = nil
	}
	r.mu.Unlock()
	if err := m.send(0, smCSTAttachOK, enc); err != nil {
		return
	}
	// Повтор только неподтверждённых S2C-дельт, с тегами НОВОГО поколения.
	for _, ch := range tail {
		f.mu.Lock()
		still := f.attached && f.attachedTo == m && f.gen == gen && !f.closing
		f.mu.Unlock()
		if !still {
			return
		}
		d := &CSTDelta{Version: 1, ID: f.id, Dir: CSTDirS2C, Gen: gen, Offset: ch.off, Dep: ch.off, Payload: ch.data}
		if err := m.send(0, smCSTDelta, d.Encode(f.fc)); err != nil {
			return
		}
	}
	vsSignal(f.spaceCh)
}

// handleDetach — штатное отсоединение: поток остаётся в реестре, ячейка
// освобождается; detached-потоки попадают в LRU (лимит -> вытеснение,
// fail closed).
func (r *FlowRegistry) handleDetach(m *Mux, p []byte) {
	d, err := DecodeCSTDetach(p)
	if err != nil {
		return
	}
	r.mu.Lock()
	f := r.flows[d.ID]
	r.mu.Unlock()
	if f == nil {
		return
	}
	f.mu.Lock()
	if f.closing || !f.attached || f.attachedTo != m || d.Gen != f.gen || !d.VerifyTag(f.fc) {
		f.mu.Unlock()
		return
	}
	f.attached = false
	f.attachedTo = nil
	f.detachedAt = time.Now()
	f.mu.Unlock()
	r.mu.Lock()
	if r.lru.Len() >= r.limits.MaxDetached {
		if e := r.lru.Back(); e != nil {
			if of, ok := e.Value.(*FlowState); ok {
				r.lru.Remove(e)
				of.lruElem = nil
				go r.closeFlow(of, CSTCloseLimits, true)
			}
		}
	}
	if f.lruElem == nil {
		f.lruElem = r.lru.PushFront(f)
	}
	r.mu.Unlock()
}

// handleSnapshot — snapshot/compaction от клиента: без payload; после
// проверки MAC освобождаем replay ниже подтверждённых границ.
func (r *FlowRegistry) handleSnapshot(m *Mux, p []byte) {
	s, err := DecodeCSTSnapshot(p)
	if err != nil {
		return
	}
	r.mu.Lock()
	f := r.flows[s.ID]
	r.mu.Unlock()
	if f == nil {
		return
	}
	f.mu.Lock()
	if f.closing || !f.attached || f.attachedTo != m || s.Gen != f.gen || !s.VerifyMAC(f.fc) {
		f.mu.Unlock()
		return
	}
	if s.ExpiryMs > 0 && time.Now().UnixMilli() > s.ExpiryMs {
		f.mu.Unlock()
		return
	}
	var freed int64
	if s.S2CAcked > f.s2cAcked && s.S2CAcked <= f.s2cNext {
		freed = f.trimS2CLocked(s.S2CAcked)
	}
	f.mu.Unlock()
	if freed > 0 {
		r.subReplay(freed)
		vsSignal(f.spaceCh)
	}
}

// handleClose — клиент закрыл поток: принимается с текущей привязанной
// ячейки (или для detached-потока — владение доказывает HMAC).
func (r *FlowRegistry) handleClose(m *Mux, p []byte) {
	c, err := DecodeCSTClose(p)
	if err != nil {
		return
	}
	r.mu.Lock()
	f := r.flows[c.ID]
	r.mu.Unlock()
	if f == nil {
		return
	}
	f.mu.Lock()
	ok := !f.closing && (f.attachedTo == m || !f.attached) && c.VerifyTag(f.fc)
	f.mu.Unlock()
	if !ok {
		return
	}
	r.closeFlow(f, c.Reason, false)
}

// --- насосы потока (по 2 горутины на поток, выходят по done) ---

func (f *FlowState) boundary() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.c2sBoundary
}

// writeEgress — запись в соединение нода->цель. UDP поверх каскада
// кадрируется [u16 len][data] (семантика serveUDPChain не меняется).
func (f *FlowState) writeEgress(p []byte) bool {
	if f.mode == CSTModeUDP && f.chainUDP {
		if len(p) > 65535 {
			return false
		}
		var lb [2]byte
		binary.BigEndian.PutUint16(lb[:], uint16(len(p)))
		if _, err := f.egress.Write(lb[:]); err != nil {
			return false
		}
	}
	_, err := f.egress.Write(p)
	return err == nil
}

// writerLoop — C2S: очередь потока -> egress по порядку, затем ACK границы.
// Ошибка egress = соединение нода->цель умерло -> поток закрывается (НИКАКОГО
// автоматического повтора прикладного запроса по новому egress).
func (f *FlowState) writerLoop() {
	defer f.reg.wg.Done()
	for {
		select {
		case <-f.done:
			return
		case item := <-f.c2sQ:
			if f.mode == CSTModeUDP {
				if !f.writeEgress(item.data) {
					f.reg.closeFlow(f, CSTCloseEgressLost, true)
					return
				}
				continue // UDP без knowledge ACK
			}
			if !f.writeEgress(item.data) {
				f.reg.closeFlow(f, CSTCloseEgressLost, true)
				return
			}
			f.mu.Lock()
			f.c2sBoundary += uint64(len(item.data))
			f.mu.Unlock()
			for { // дренируем pending строго по границе
				f.mu.Lock()
				d, ok := f.c2sPending[f.c2sBoundary]
				f.mu.Unlock()
				if !ok {
					break
				}
				if !f.writeEgress(d.Payload) {
					f.reg.closeFlow(f, CSTCloseEgressLost, true)
					return
				}
				f.mu.Lock()
				delete(f.c2sPending, f.c2sBoundary)
				f.c2sBoundary += uint64(len(d.Payload))
				f.mu.Unlock()
			}
			f.sendAckTo(f.boundary())
		}
	}
}

// sendAckTo — knowledge ACK ноды клиенту: граница C2S записана в egress.
func (f *FlowState) sendAckTo(boundary uint64) {
	f.mu.Lock()
	m := f.attachedTo
	gen := f.gen
	f.mu.Unlock()
	if m == nil {
		return
	}
	a := &CSTAck{Version: 1, ID: f.id, Dir: CSTDirC2S, Gen: gen, Ack: boundary}
	_ = m.send(0, smCSTAck, a.Encode(f.fc))
}

// waitReplaySpace — backpressure насоса: replay-окно ограничено; ждём ACK,
// закрытия или вытеснения. Память не растёт сверх лимита ни на мгновение.
func (f *FlowState) waitReplaySpace() bool {
	for {
		f.mu.Lock()
		ok := f.replayBytes <= f.reg.limits.MaxReplayBytesPerFlow
		closing := f.closing
		f.mu.Unlock()
		if ok {
			return true
		}
		if closing {
			return false
		}
		select {
		case <-f.spaceCh:
		case <-f.done:
			return false
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// emitDelta — S2C: байты из egress -> дельта клиенту + replay-окно (TCP).
// При DETACHED накапливаем в replay (bounded) — клиент получит после attach.
func (f *FlowState) emitDelta(data []byte, isUDP bool) {
	f.mu.Lock()
	if f.closing {
		f.mu.Unlock()
		return
	}
	off := f.s2cNext
	f.s2cNext += uint64(len(data))
	gen := f.gen
	if !isUDP {
		f.s2cReplay = append(f.s2cReplay, replayChunk{off: off, data: data})
		f.replayBytes += int64(len(data))
	}
	m := f.attachedTo
	attached := f.attached
	f.mu.Unlock()
	if !isUDP {
		f.reg.addReplay(f, int64(len(data)))
		if !f.waitReplaySpace() {
			return
		}
	}
	if !attached || m == nil {
		return
	}
	d := &CSTDelta{Version: 1, ID: f.id, Dir: CSTDirS2C, Gen: gen, Offset: off, Dep: off, Payload: data}
	if isUDP {
		d.Flags = CSTFlagDatagram
		d.ExpiryMs = time.Now().Add(10 * time.Second).UnixMilli()
	}
	_ = m.send(0, smCSTDelta, d.Encode(f.fc))
}

// pumpLoop — чтение из egress: TCP потоком, UDP датаграммами (у каскада —
// u16-кадрировка). EOF/ошибка = egress умер -> корректное закрытие потока
// с CSTClose клиенту.
func (f *FlowState) pumpLoop() {
	defer f.reg.wg.Done()
	buf := make([]byte, maxCSTPayload)
	for {
		if f.mode == CSTModeUDP {
			if f.chainUDP {
				var lb [2]byte
				if _, err := io.ReadFull(f.egress, lb[:]); err != nil {
					f.reg.closeFlow(f, CSTCloseEgressLost, true)
					return
				}
				l := int(binary.BigEndian.Uint16(lb[:]))
				if l == 0 || l > maxCSTDatagram {
					f.reg.closeFlow(f, CSTCloseEgressLost, true)
					return
				}
				d := make([]byte, l)
				if _, err := io.ReadFull(f.egress, d); err != nil {
					f.reg.closeFlow(f, CSTCloseEgressLost, true)
					return
				}
				f.emitDelta(d, true)
				continue
			}
			n, err := f.egress.Read(buf[:maxCSTDatagram])
			if n > 0 {
				f.emitDelta(append([]byte(nil), buf[:n]...), true)
			}
			if err != nil {
				f.reg.closeFlow(f, CSTCloseEgressLost, true)
				return
			}
			continue
		}
		n, err := f.egress.Read(buf)
		if n > 0 {
			f.emitDelta(append([]byte(nil), buf[:n]...), false)
		}
		if err != nil {
			f.reg.closeFlow(f, CSTCloseEgressLost, true)
			return
		}
	}
}

// detachMux — смерть серверного Mux: его потоки -> DETACHED (LRU, лимит
// detached с вытеснением, fail closed). Вызывается из serveMuxWithConfig
// после завершения цикла чтения ячейки.
func (r *FlowRegistry) detachMux(m *Mux) {
	r.mu.Lock()
	var fs []*FlowState
	for _, f := range r.flows {
		fs = append(fs, f)
	}
	r.mu.Unlock()
	for _, f := range fs {
		f.mu.Lock()
		if f.closing || !f.attached || f.attachedTo != m {
			f.mu.Unlock()
			continue
		}
		f.attached = false
		f.attachedTo = nil
		f.detachedAt = time.Now()
		f.mu.Unlock()
		r.mu.Lock()
		if r.lru.Len() >= r.limits.MaxDetached {
			if e := r.lru.Back(); e != nil {
				if of, ok := e.Value.(*FlowState); ok {
					r.lru.Remove(e)
					of.lruElem = nil
					go r.closeFlow(of, CSTCloseLimits, true)
				}
			}
		}
		if f.lruElem == nil {
			f.lruElem = r.lru.PushFront(f)
		}
		r.mu.Unlock()
	}
}
