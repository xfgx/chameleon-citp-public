package chameleon

// knowledge.go — CST: Knowledge Layer клиента. Стоит МЕЖДУ локальными
// SOCKS/TUN-потоками и сменяемыми Mux/transport cells:
//
//	SOCKS/TUN -> VirtualStream -> KnowledgeLayer -> Mux/cell -> transport.go
//
// Ячейка — конкретное TCP или WSS соединение; её потеря НЕ уничтожает
// логические потоки: KnowledgeLayer переводит их в DETACHED, поднимает новую
// ячейку (через onDead -> Manager), согласует capability, шлёт манифесты,
// согласует knowledge boundaries и повторяет только неподтверждённые дельты.
//
// CST не включается до согласования capability обеими сторонами; нода без
// CST молчит на smCSTCap -> клиент откатывается на legacy open (fail-safe).

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// cstHandlers — обработчики CST-кадров мультиплексора (клиент или нода).
// Deltas/ACK — горячий путь: вызываются инлайн из цикла чтения и ОБЯЗАНЫ
// не блокироваться (медленный поток не имеет права вешать глобальный Mux).
type cstHandlers struct {
	onHello     func(m *Mux, p []byte)
	onOpen      func(m *Mux, p []byte)
	onOpenOK    func(m *Mux, p []byte)
	onOpenErr   func(m *Mux, p []byte)
	onDelta     func(m *Mux, p []byte)
	onAck       func(m *Mux, p []byte)
	onAttach    func(m *Mux, p []byte)
	onAttachOK  func(m *Mux, p []byte)
	onAttachErr func(m *Mux, p []byte)
	onDetach    func(m *Mux, p []byte)
	onSnapshot  func(m *Mux, p []byte)
	onClose     func(m *Mux, p []byte)
}

// cstBinding — атомарно подменяемая связка Mux -> knowledge-слой.
type cstBinding struct {
	h      *cstHandlers
	onKill func(err error)
}

// SetCSTBinding — единственная точка подключения CST к Mux (потокобезопасно).
func (m *Mux) SetCSTBinding(b *cstBinding) { m.cstB.Store(b) }

// cstTargetKey — канонический ключ цели для continuity key: одинаково
// вычисляется клиентом и нодой.
func cstTargetKey(mode uint8, canonical string) string {
	if mode == CSTModeUDP {
		return "udp:" + canonical
	}
	return "tcp:" + canonical
}

// cstErrUnknownFlow — маркер «нода поток не знает» (восстанавливать нечего).
const cstErrUnknownFlow = "unknown flow"

// KnowledgeLayer — клиентский реестр VirtualStream и точка восстановления.
type KnowledgeLayer struct {
	mu         sync.Mutex
	flows      map[FlowID]*VirtualStream
	mux        *Mux
	muxSeq     uint64
	negotiated bool
	clientPub  []byte
	nodePub    []byte
	logf       func(string, ...any)

	restoreTimeout time.Duration // дедлайн восстановления DETACHED-потока
	negTimeout     time.Duration // таймаут capability negotiation
	openTimeout    time.Duration // таймаут open/attach
	onDead         func()        // триггер Manager: поднять новую ячейку
}

func NewKnowledgeLayer(clientPub, nodePub []byte, logf func(string, ...any)) *KnowledgeLayer {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &KnowledgeLayer{
		flows:          make(map[FlowID]*VirtualStream),
		clientPub:      append([]byte(nil), clientPub...),
		nodePub:        append([]byte(nil), nodePub...),
		logf:           logf,
		restoreTimeout: 90 * time.Second,
		negTimeout:     3 * time.Second,
		openTimeout:    15 * time.Second,
	}
}

// SetOnDead — колбэк «ячейка умерла» (Manager переподключается асинхронно).
func (kl *KnowledgeLayer) SetOnDead(fn func()) {
	kl.mu.Lock()
	kl.onDead = fn
	kl.mu.Unlock()
}

// Active — CST согласован на живой ячейке.
func (kl *KnowledgeLayer) Active() bool {
	kl.mu.Lock()
	defer kl.mu.Unlock()
	return kl.negotiated && kl.mux != nil && kl.mux.Alive()
}

// HasFlows — есть ли живые логические потоки (для безопасного fallback:
// при их наличии на не-CST ячейку откатываться НЕЛЬЗЯ — fail closed).
func (kl *KnowledgeLayer) HasFlows() bool {
	kl.mu.Lock()
	defer kl.mu.Unlock()
	return len(kl.flows) > 0
}

// NodePub — ключ ноды, к которой привязан слой (cross-node защита).
func (kl *KnowledgeLayer) NodePub() []byte { return kl.nodePub }

func (kl *KnowledgeLayer) flow(id FlowID) *VirtualStream {
	kl.mu.Lock()
	defer kl.mu.Unlock()
	return kl.flows[id]
}

func (kl *KnowledgeLayer) removeFlow(id FlowID) {
	kl.mu.Lock()
	delete(kl.flows, id)
	kl.mu.Unlock()
}

func (kl *KnowledgeLayer) currentMux() *Mux {
	kl.mu.Lock()
	defer kl.mu.Unlock()
	if kl.mux != nil && kl.mux.Alive() {
		return kl.mux
	}
	return nil
}

// BindMux — новая transport cell: вешаем обработчики, запускаем
// capability negotiation; при успехе — attach всех DETACHED-потоков.
func (kl *KnowledgeLayer) BindMux(m *Mux) {
	kl.mu.Lock()
	kl.mux = m
	kl.negotiated = false
	kl.muxSeq++
	seq := kl.muxSeq
	kl.mu.Unlock()
	m.SetCSTBinding(&cstBinding{
		h:      kl.handlers(),
		onKill: func(err error) { kl.muxDied(m, err) },
	})
	kl.logf("cst: новая ячейка #%d, согласование возможностей...", seq)
	go kl.negotiate(m, seq)
}

// negotiate — capability negotiation: CSTHello -> ответ ноды (negTimeout).
// Молчание = нода без CST -> legacy fallback (новые потоки — по-старому).
func (kl *KnowledgeLayer) negotiate(m *Mux, seq uint64) {
	hello := (&CSTHello{Version: CSTVersion, Flags: CSTFlagSupported}).Encode()
	if err := m.send(0, smCSTCap, hello); err != nil {
		return
	}
	deadline := time.Now().Add(kl.negTimeout)
	for time.Now().Before(deadline) {
		kl.mu.Lock()
		ok := kl.negotiated && kl.mux == m
		kl.mu.Unlock()
		if ok {
			kl.logf("cst: нода согласовала CST v%d — knowledge-слой активен", CSTVersion)
			kl.attachAll(m, seq)
			return
		}
		if !m.Alive() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	kl.mu.Lock()
	stillCurrent := kl.mux == m && !kl.negotiated
	kl.mu.Unlock()
	if stillCurrent && m.Alive() {
		kl.logf("cst: нода не ответила на capability — legacy-режим (fallback)")
	}
}

// muxDied — смерть ячейки: потоки НЕ закрываем, переводим в DETACHED.
// Реагируем только на смерть ТЕКУЩЕЙ ячейки (старые mux нас не трогают).
func (kl *KnowledgeLayer) muxDied(m *Mux, err error) {
	kl.mu.Lock()
	if kl.mux != m {
		kl.mu.Unlock()
		return
	}
	kl.mux = nil
	kl.negotiated = false
	var flows []*VirtualStream
	for _, vs := range kl.flows {
		flows = append(flows, vs)
	}
	onDead := kl.onDead
	kl.mu.Unlock()
	n := 0
	for _, vs := range flows {
		vs.mu.Lock()
		st := vs.state
		vs.mu.Unlock()
		if st == VSOpening {
			select {
			case vs.openCh <- errVSClosed:
			default:
			}
			vs.finalize(VSClosed, false) // не открывшийся поток восстановить нечем
			continue
		}
		if st == VSResuming {
			select {
			case vs.attachCh <- attachResult{err: errVSClosed}:
			default:
			}
		}
		vs.detach()
		n++
	}
	kl.logf("cst: ячейка умерла (%v) — %d потоков в DETACHED, восстановление...", err, n)
	if onDead != nil {
		go onDead()
	}
}

// attachAll — attach всех DETACHED-потоков к свежей ячейке.
func (kl *KnowledgeLayer) attachAll(m *Mux, seq uint64) {
	kl.mu.Lock()
	var detached []*VirtualStream
	for _, vs := range kl.flows {
		vs.mu.Lock()
		if vs.state == VSDetached {
			detached = append(detached, vs)
		}
		vs.mu.Unlock()
	}
	kl.mu.Unlock()
	for _, vs := range detached {
		kl.attachFlow(vs, m, seq)
	}
}

var errVSUnknownFlow = errors.New("cst: " + cstErrUnknownFlow)

func chunksLen(ch []replayChunk) int64 {
	var n int64
	for _, c := range ch {
		n += int64(len(c.data))
	}
	return n
}

// attachFlow — манифест + согласование границ + повтор неподтверждённых дельт.
func (kl *KnowledgeLayer) attachFlow(vs *VirtualStream, m *Mux, seq uint64) {
	vs.mu.Lock()
	if vs.state != VSDetached {
		vs.mu.Unlock()
		return
	}
	vs.state = VSResuming
	vs.gen++
	gen := vs.gen
	vs.attachCh = make(chan attachResult, 1)
	ach := vs.attachCh
	at := &CSTAttach{
		Version: 1, ID: vs.id, NewGen: gen,
		ClientS2CAcked: vs.recvBoundary,
		ClientC2SAcked: vs.sendAcked,
		ExpiryMs:       time.Now().Add(30 * time.Second).UnixMilli(),
	}
	_, _ = rand.Read(at.Nonce[:])
	vs.mu.Unlock()
	kl.mu.Lock()
	cur := kl.mux == m && kl.muxSeq == seq
	kl.mu.Unlock()
	if !cur {
		vs.mu.Lock()
		vs.state = VSDetached
		vs.mu.Unlock()
		return
	}
	if err := m.send(0, smCSTAttach, at.Encode(vs.fc, m.conn.seed)); err != nil {
		vs.mu.Lock()
		vs.state = VSDetached
		vs.mu.Unlock()
		return
	}
	t := time.NewTimer(kl.openTimeout)
	defer t.Stop()
	select {
	case res := <-ach:
		if res.err != nil {
			vs.mu.Lock()
			if vs.state == VSResuming {
				if errors.Is(res.err, errVSUnknownFlow) {
					vs.mu.Unlock()
					vs.finalize(VSClosed, false)
					kl.logf("cst: поток %x неизвестен ноде — закрыт", vs.id[:4])
					return
				}
				vs.state = VSDetached
			}
			vs.mu.Unlock()
			vsSignal(vs.spaceCh)
			return
		}
		vs.mu.Lock()
		if vs.state != VSResuming {
			vs.mu.Unlock()
			return
		}
		// Нода подтвердила приём до nodeC2S — подрезаем replay, шлём хвост.
		if res.nodeC2S > vs.sendAcked && res.nodeC2S <= vs.sendOff {
			vs.trimLocked(res.nodeC2S)
		}
		tail := append([]replayChunk(nil), vs.replay...)
		vs.state = VSAttached
		vs.detachDeadline = time.Time{}
		vs.mu.Unlock()
		kl.logf("cst: поток %x восстановлен (gen=%d, повтор %d байт)", vs.id[:4], gen, chunksLen(tail))
		for _, ch := range tail {
			kl.sendDelta(vs, ch.off, ch.data, 0, 0)
		}
		vsSignal(vs.spaceCh)
	case <-t.C:
		vs.mu.Lock()
		if vs.state == VSResuming {
			vs.state = VSDetached
		}
		vs.mu.Unlock()
	case <-vs.dead:
	}
}

// OpenFlow открывает логический поток через текущую ячейку: DNS-binding
// для доменов (RESOLVE+RO, как у Mux.Open), FlowSecret едет один раз внутри
// AEAD-сеанса, клиент после OpenOK хранит только continuity key.
func (kl *KnowledgeLayer) OpenFlow(target string, mode uint8) (*VirtualStream, error) {
	kl.mu.Lock()
	m := kl.mux
	ok := kl.negotiated
	kl.mu.Unlock()
	if m == nil || !ok || !m.Alive() {
		return nil, errVSNoCST
	}
	var roB []byte
	canonical := target
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	if mode != CSTModeUDP && net.ParseIP(strings.Trim(host, "[]")) == nil {
		domain := strings.ToLower(strings.TrimSuffix(host, "."))
		ro, rerr := m.Resolve(domain)
		if rerr != nil {
			return nil, fmt.Errorf("cst: resolve %s: %w", domain, rerr)
		}
		if len(ro.Addrs) == 0 {
			return nil, fmt.Errorf("cst: resolve %s: пустой ответ", domain)
		}
		roB = ro.Encode()
		canonical = net.JoinHostPort(ro.Addrs[0], port)
	}
	enc, err := EncodeTarget(canonical)
	if err != nil {
		return nil, err
	}
	if mode == CSTModeUDP {
		enc = EncodeUDPTarget(target)
		canonical = target
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return nil, err
	}
	id := NewFlowID()
	fc := DeriveContinuity(secret[:], kl.clientPub, kl.nodePub, id, cstTargetKey(mode, canonical))
	vs := newVirtualStream(kl, id, fc, canonical, mode)
	kl.mu.Lock()
	kl.flows[id] = vs
	kl.mu.Unlock()
	open := &CSTOpen{Version: CSTVersion, ID: id, Secret: secret, Mode: mode, RO: roB, Target: enc}
	if err := m.send(0, smCSTOpen, open.Encode()); err != nil {
		kl.removeFlow(id)
		return nil, err
	}
	t := time.NewTimer(kl.openTimeout)
	defer t.Stop()
	select {
	case err := <-vs.openCh:
		if err != nil {
			vs.finalize(VSClosed, false)
			return nil, err
		}
		vs.mu.Lock()
		vs.state = VSAttached
		vs.mu.Unlock()
		ZeroizeBytes(secret[:]) // клиент хранит только CK
		kl.logf("cst: поток %x -> %s открыт (gen=1)", id[:4], canonical)
		return vs, nil
	case <-t.C:
		vs.finalize(VSClosed, false)
		return nil, fmt.Errorf("cst: таймаут open")
	case <-vs.dead:
		return nil, errVSClosed
	}
}

// handlers — клиентский набор обработчиков CST-кадров.
func (kl *KnowledgeLayer) handlers() *cstHandlers {
	return &cstHandlers{
		onHello: func(m *Mux, p []byte) {
			h, err := DecodeCSTHello(p)
			if err != nil || h.Flags&CSTFlagSupported == 0 {
				return
			}
			kl.mu.Lock()
			if kl.mux == m && !kl.negotiated { // согласованное CST не понижается
				kl.negotiated = true
			}
			kl.mu.Unlock()
		},
		onOpenOK: func(m *Mux, p []byte) {
			msg, err := DecodeCSTOpenOK(p)
			if err != nil {
				return
			}
			if vs := kl.flow(msg.ID); vs != nil {
				select {
				case vs.openCh <- nil:
				default:
				}
			}
		},
		onOpenErr: func(m *Mux, p []byte) {
			e, err := DecodeCSTErr(p)
			if err != nil {
				return
			}
			if vs := kl.flow(e.ID); vs != nil {
				select {
				case vs.openCh <- errors.New("cst: нода отклонила open: " + e.Msg):
				default:
				}
			}
		},
		onDelta: func(m *Mux, p []byte) {
			d, err := DecodeCSTDelta(p)
			if err != nil {
				return
			}
			if vs := kl.flow(d.ID); vs != nil {
				vs.onDelta(d)
			}
		},
		onAck: func(m *Mux, p []byte) {
			a, err := DecodeCSTAck(p)
			if err != nil {
				return
			}
			if vs := kl.flow(a.ID); vs != nil {
				vs.onAck(a)
			}
		},
		onAttachOK: func(m *Mux, p []byte) {
			msg, err := DecodeCSTAttachOK(p)
			if err != nil {
				return
			}
			vs := kl.flow(msg.ID)
			if vs == nil || !msg.VerifyMAC(vs.fc, m.conn.seed) {
				return
			}
			select {
			case vs.attachCh <- attachResult{nodeC2S: msg.NodeC2SBoundary, nodeS2CNext: msg.NodeS2CNext}:
			default:
			}
		},
		onAttachErr: func(m *Mux, p []byte) {
			e, err := DecodeCSTErr(p)
			if err != nil {
				return
			}
			vs := kl.flow(e.ID)
			if vs == nil {
				return
			}
			rerr := errors.New("cst: attach отклонён: " + e.Msg)
			if strings.HasPrefix(e.Msg, cstErrUnknownFlow) {
				rerr = errVSUnknownFlow
			}
			select {
			case vs.attachCh <- attachResult{err: rerr}:
			default:
			}
		},
		onClose: func(m *Mux, p []byte) {
			c, err := DecodeCSTClose(p)
			if err != nil {
				return
			}
			vs := kl.flow(c.ID)
			if vs == nil || !c.VerifyTag(vs.fc) {
				return
			}
			vs.onPeerClose(c.Reason)
		},
		onSnapshot: func(m *Mux, p []byte) {
			s, err := DecodeCSTSnapshot(p)
			if err != nil {
				return
			}
			if vs := kl.flow(s.ID); vs != nil {
				vs.onSnapshot(s)
			}
		},
	}
}

// sendDelta — исходящая C2S-дельта через текущую ячейку.
func (kl *KnowledgeLayer) sendDelta(vs *VirtualStream, off uint64, data []byte, flags uint8, expiryMs int64) {
	m := kl.currentMux()
	if m == nil {
		vs.detach()
		return
	}
	vs.mu.Lock()
	gen := vs.gen
	vs.mu.Unlock()
	d := &CSTDelta{Version: 1, ID: vs.id, Dir: CSTDirC2S, Flags: flags, Gen: gen, Offset: off, Dep: off, ExpiryMs: expiryMs, Payload: data}
	if err := m.send(0, smCSTDelta, d.Encode(vs.fc)); err != nil {
		kl.muxDied(m, err)
	}
}

// sendAck — knowledge ACK по направлению S2C (клиент доставил потребителю).
func (kl *KnowledgeLayer) sendAck(vs *VirtualStream, boundary uint64) {
	m := kl.currentMux()
	if m == nil {
		return
	}
	vs.mu.Lock()
	gen := vs.gen
	vs.mu.Unlock()
	a := &CSTAck{Version: 1, ID: vs.id, Dir: CSTDirS2C, Gen: gen, Ack: boundary}
	if err := m.send(0, smCSTAck, a.Encode(vs.fc)); err != nil {
		kl.muxDied(m, err)
	}
}

// sendClose — CSTClose ноде (штатное закрытие потока).
func (kl *KnowledgeLayer) sendClose(vs *VirtualStream) {
	m := kl.currentMux()
	if m == nil {
		return
	}
	c := &CSTClose{Version: 1, ID: vs.id, Reason: CSTCloseNormal}
	_ = m.send(0, smCSTClose, c.Encode(vs.fc))
}

// CloseAll — закрытие всех потоков (Disconnect клиента): не DETACHED, а
// финальное закрытие с уведомлением ноды.
func (kl *KnowledgeLayer) CloseAll() {
	kl.mu.Lock()
	var flows []*VirtualStream
	for _, vs := range kl.flows {
		flows = append(flows, vs)
	}
	kl.mu.Unlock()
	for _, vs := range flows {
		vs.finalize(VSClosed, true)
	}
}
