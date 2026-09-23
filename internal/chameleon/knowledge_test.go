package chameleon

// knowledge_test.go — CST: помощник окружения (loopback-нода с реестром +
// эхо-«интернет»), каноничность кодека, fuzz-таргеты новых декодеров.

import (
	"encoding/base64"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// cstTestNode — тестовая нода с FlowRegistry и эхо-целью на loopback.
type cstTestNode struct {
	t            *testing.T
	echoLn       net.Listener
	nodeLn       net.Listener
	reg          *FlowRegistry
	nodePubB64   string
	clientKeyB64 string
	clientPub    []byte
	nodePub      []byte
	mu           sync.Mutex
	echoConns    []net.Conn
}

func newCSTTestNode(t *testing.T, limits *FlowLimits) *cstTestNode {
	t.Helper()
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	nodePrivB64, nodePubB64, err := GenerateNodeKey()
	if err != nil {
		t.Fatal(err)
	}
	nodePriv, err := ParseNodePrivKey(nodePrivB64)
	if err != nil {
		t.Fatal(err)
	}
	clientB64, clientPubB64, err := GenerateNodeKey()
	if err != nil {
		t.Fatal(err)
	}
	clientPub, _ := base64.RawURLEncoding.DecodeString(clientPubB64)
	nodePub, _ := base64.RawURLEncoding.DecodeString(nodePubB64)
	if limits == nil {
		l := DefaultFlowLimits()
		limits = &l
	}
	reg := NewFlowRegistry(*limits, nodePub)
	nodeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tn := &cstTestNode{t: t, echoLn: echoLn, nodeLn: nodeLn, reg: reg,
		nodePubB64: nodePubB64, clientKeyB64: clientB64, clientPub: clientPub, nodePub: nodePub}
	go func() { // «интернет»: эхо
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			tn.mu.Lock()
			tn.echoConns = append(tn.echoConns, c)
			tn.mu.Unlock()
			go io.Copy(c, c)
		}
	}()
	go func() { // нода
		for {
			c, err := nodeLn.Accept()
			if err != nil {
				return
			}
			go func() {
				sess, cpub, err := ServerHandshake(c, nodePriv, nil)
				if err != nil {
					return
				}
				conn, err := NewServerConn(c, sess)
				if err != nil {
					return
				}
				ServeMuxWithCST(conn, 5*time.Second,
					NewPolicyEngine(DeclarativePolicy{MaxStreamsPerConn: 256}), nil,
					nil, nil, false,
					&CSTServerConfig{Registry: reg, NodePub: nodePub, ClientPub: cpub})
			}()
		}
	}()
	return tn
}

// dial — новая клиентская ячейка (физическая сессия + mux).
func (n *cstTestNode) dial(t *testing.T) (*Mux, *Conn) {
	t.Helper()
	cc, err := DialNode(n.nodeLn.Addr().String(), n.nodePubB64, n.clientKeyB64, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return NewMuxClient(cc), cc
}

// newKL — KnowledgeLayer клиента с тестовыми таймаутами.
func (n *cstTestNode) newKL() *KnowledgeLayer {
	kl := NewKnowledgeLayer(n.clientPub, n.nodePub, nil)
	kl.negTimeout = 500 * time.Millisecond
	kl.openTimeout = 5 * time.Second
	kl.restoreTimeout = 3 * time.Second
	return kl
}

func (n *cstTestNode) echoTarget() string { return n.echoLn.Addr().String() }

func (n *cstTestNode) echoConnCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.echoConns)
}

func (n *cstTestNode) Close() {
	n.reg.Shutdown()
	n.nodeLn.Close()
	n.echoLn.Close()
}

// waitFor — детерминированный опрос условия (без внешней сети).
func waitFor(t *testing.T, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout: %s", what)
}

// readFull — прочитать ровно n байт из потока с дедлайном.
func readFull(t *testing.T, vs *VirtualStream, n int) []byte {
	t.Helper()
	vs.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer vs.SetReadDeadline(time.Time{})
	buf := make([]byte, n)
	_, err := io.ReadFull(vs, buf)
	if err != nil {
		t.Fatalf("readFull(%d): %v", n, err)
	}
	return buf
}

// --- Каноничность кодека ---

func TestCSTCodecCanonical(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	id := NewFlowID()
	fc := DeriveContinuity(secret, []byte("cp32cp32cp32cp32cp32cp32cp32cp32"), []byte("np32np32np32np32np32np32np32np32"), id, "tcp:127.0.0.1:80")

	// Hello roundtrip + trailing data.
	h := (&CSTHello{Version: CSTVersion, Flags: CSTFlagSupported}).Encode()
	if _, err := DecodeCSTHello(h); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeCSTHello(append(h, 0x00)); err == nil {
		t.Fatal("hello: trailing data принят")
	}
	if _, err := DecodeCSTHello(h[:3]); err == nil {
		t.Fatal("hello: усечение принято")
	}

	// Open roundtrip + trailing + невалидные длины + неверный MAC.
	open := &CSTOpen{Version: CSTVersion, ID: id, Mode: CSTModeTCP, Target: []byte("atyp-target")}
	copy(open.Secret[:], secret)
	oe := open.Encode()
	o2, err := DecodeCSTOpen(oe)
	if err != nil || o2.ID != id || o2.Mode != CSTModeTCP {
		t.Fatalf("open roundtrip: %v", err)
	}
	if _, err := DecodeCSTOpen(append(oe, 0x00)); err == nil {
		t.Fatal("open: trailing data принят")
	}
	badMAC := append([]byte(nil), oe...)
	badMAC[len(badMAC)-1] ^= 0xff
	if _, err := DecodeCSTOpen(badMAC); err == nil {
		t.Fatal("open: неверный MAC принят")
	}

	// Delta roundtrip + trailing + allocation bomb + неверное направление.
	d := &CSTDelta{Version: 1, ID: id, Dir: CSTDirC2S, Gen: 1, Offset: 42, Dep: 42, Payload: []byte("payload")}
	de := d.Encode(fc)
	d2, err := DecodeCSTDelta(de)
	if err != nil || d2.Offset != 42 || string(d2.Payload) != "payload" || !d2.VerifyTag(fc) {
		t.Fatalf("delta roundtrip: %v", err)
	}
	if _, err := DecodeCSTDelta(append(de, 0x00)); err == nil {
		t.Fatal("delta: trailing data принят")
	}
	bomb := make([]byte, cstDeltaHeadLen+cstTagLen)
	bomb[0] = 1
	bomb[17] = CSTDirC2S
	bomb[47], bomb[48], bomb[49], bomb[50] = 0xff, 0xff, 0xff, 0xff // payloadLen = 4 GiB
	if _, err := DecodeCSTDelta(bomb); err == nil {
		t.Fatal("delta: allocation bomb принят")
	}
	d3 := &CSTDelta{Version: 1, ID: id, Dir: 9, Gen: 1, Payload: []byte("x")}
	if _, err := DecodeCSTDelta(d3.Encode(fc)); err == nil {
		t.Fatal("delta: неизвестное направление принято")
	}

	// Ack/Attach/Detach/Close/Snapshot roundtrip + trailing.
	a := &CSTAck{Version: 1, ID: id, Dir: CSTDirS2C, Gen: 3, Ack: 777}
	ae := a.Encode(fc)
	if a2, err := DecodeCSTAck(ae); err != nil || a2.Ack != 777 || !a2.VerifyTag(fc) {
		t.Fatal("ack roundtrip")
	}
	if _, err := DecodeCSTAck(append(ae, 1)); err == nil {
		t.Fatal("ack: trailing")
	}
	at := &CSTAttach{Version: 1, ID: id, NewGen: 2, ClientS2CAcked: 5, ClientC2SAcked: 6, ExpiryMs: 9}
	ate := at.Encode(fc, []byte("sess"))
	if at2, err := DecodeCSTAttach(ate); err != nil || at2.NewGen != 2 || !at2.VerifyMAC(fc, []byte("sess")) {
		t.Fatal("attach roundtrip")
	}
	if _, err := DecodeCSTAttach(append(ate, 1)); err == nil {
		t.Fatal("attach: trailing")
	}
	aok := &CSTAttachOK{Version: 1, ID: id, Gen: 2, NodeC2SBoundary: 11, NodeS2CNext: 22}
	aoke := aok.Encode(fc, []byte("sess"))
	if ao2, err := DecodeCSTAttachOK(aoke); err != nil || ao2.NodeS2CNext != 22 || !ao2.VerifyMAC(fc, []byte("sess")) {
		t.Fatal("attach-ok roundtrip")
	}
	det := &CSTDetach{Version: 1, ID: id, Gen: 2}
	if d22, err := DecodeCSTDetach(det.Encode(fc)); err != nil || !d22.VerifyTag(fc) {
		t.Fatal("detach roundtrip")
	}
	cl := &CSTClose{Version: 1, ID: id, Reason: CSTCloseEgressLost}
	if c2, err := DecodeCSTClose(cl.Encode(fc)); err != nil || c2.Reason != CSTCloseEgressLost || !c2.VerifyTag(fc) {
		t.Fatal("close roundtrip")
	}
	sn := &CSTSnapshot{Version: 1, ID: id, Gen: 2, C2SAcked: 1, S2CAcked: 2, ExpiryMs: 3}
	if s2, err := DecodeCSTSnapshot(sn.Encode(fc)); err != nil || s2.S2CAcked != 2 || !s2.VerifyMAC(fc) {
		t.Fatal("snapshot roundtrip")
	}
	ce := (&CSTErr{Version: CSTVersion, ID: id, Msg: "boom"}).Encode()
	if e2, err := DecodeCSTErr(ce); err != nil || e2.Msg != "boom" {
		t.Fatal("err roundtrip")
	}
}

// --- Fuzz-таргеты новых декодеров: ни паник, ни взрывов памяти ---

func FuzzDecodeCSTDelta(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, cstDeltaHeadLen+cstTagLen))
	f.Add([]byte("\x01some-random-cst-delta-frame-bytes-0123456789abcdef"))
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := DecodeCSTDelta(b)
		if err == nil && d != nil && len(d.Encode(nil)) == 0 { // fc nil: только длина
			t.Fatal("пустая перекодировка валидной дельты")
		}
	})
}

func FuzzDecodeCSTAttach(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, cstAttachHeadLen+cstTagLen))
	f.Fuzz(func(t *testing.T, b []byte) {
		if m, err := DecodeCSTAttach(b); err == nil && m == nil {
			t.Fatal("nil без ошибки")
		}
	})
}

func FuzzDecodeCSTOpen(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 87))
	f.Fuzz(func(t *testing.T, b []byte) {
		if o, err := DecodeCSTOpen(b); err == nil && o == nil {
			t.Fatal("nil без ошибки")
		}
	})
}

// --- E2E: разрыв физической сессии, логический поток живёт ---

// TestCSTResumeE2E — TCP cell-resume: клиент->нода восстанавливается,
// соединение нода->цель НЕ пересоздаётся, неподтверждённые дельты
// повторяются ровно один раз, порядок байт сохраняется.
func TestCSTResumeE2E(t *testing.T) {
	tn := newCSTTestNode(t, nil)
	defer tn.Close()
	mux1, cc1 := tn.dial(t)
	kl := tn.newKL()
	kl.BindMux(mux1)
	waitFor(t, "negotiate", func() bool { return kl.Active() })

	vs, err := kl.OpenFlow(tn.echoTarget(), CSTModeTCP)
	if err != nil {
		t.Fatal(err)
	}
	if vs.State() != VSAttached {
		t.Fatalf("state %s", vs.State())
	}
	if _, err := vs.Write([]byte("hello-1;")); err != nil {
		t.Fatal(err)
	}
	if got := readFull(t, vs, 8); string(got) != "hello-1;" {
		t.Fatalf("echo1 %q", got)
	}
	waitFor(t, "ack1", func() bool { _, acked, _ := vs.Offsets(); return acked == 8 })

	// Разрыв физической сессии: ячейка умирает, логический поток — нет.
	cc1.Close()
	waitFor(t, "detach", func() bool { return vs.State() == VSDetached })
	if tn.echoConnCount() != 1 {
		t.Fatalf("egress не пережил ячейку: %d соединений", tn.echoConnCount())
	}

	// Запись в DETACHED: ограниченная буферизация в replay-окно.
	if _, err := vs.Write([]byte("hello-2;")); err != nil {
		t.Fatal(err)
	}

	// Новая transport cell: capability negotiation -> манифест -> границы ->
	// повтор только неподтверждённого -> перепривязка.
	mux2, _ := tn.dial(t)
	kl.BindMux(mux2)
	waitFor(t, "reattach", func() bool { return vs.State() == VSAttached })
	if gen, _, _, _, attached, ok := tn.reg.flowInfo(vs.ID()); !ok || !attached || gen != 2 {
		t.Fatalf("после attach: gen=%d attached=%v ok=%v", gen, attached, ok)
	}

	// Буферизованные в DETACHED байты дошли ровно один раз, порядок сохранён.
	if got := readFull(t, vs, 8); string(got) != "hello-2;" {
		t.Fatalf("echo2 %q (дубль или потеря)", got)
	}
	if _, err := vs.Write([]byte("hello-3;")); err != nil {
		t.Fatal(err)
	}
	if got := readFull(t, vs, 8); string(got) != "hello-3;" {
		t.Fatalf("echo3 %q", got)
	}

	// Ключевое: соединение нода->цель всё ещё ОДНО — egress пережил смену cell.
	if tn.echoConnCount() != 1 {
		t.Fatalf("egress дублирован при attach: %d соединений", tn.echoConnCount())
	}
	vs.Close()
}

// TestCSTResumeBreakAfterDelta — разрыв сразу после записи: дельта могла не
// получить ACK (или ACK не дошёл до отправителя). После attach: ни потерь,
// ни дублей (границы + идемпотентные дубликаты).
func TestCSTResumeBreakAfterDelta(t *testing.T) {
	tn := newCSTTestNode(t, nil)
	defer tn.Close()
	mux1, cc1 := tn.dial(t)
	kl := tn.newKL()
	kl.BindMux(mux1)
	waitFor(t, "negotiate", func() bool { return kl.Active() })
	vs, err := kl.OpenFlow(tn.echoTarget(), CSTModeTCP)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vs.Write([]byte("first!!!")); err != nil {
		t.Fatal(err)
	}
	if got := readFull(t, vs, 8); string(got) != "first!!!" {
		t.Fatalf("echo1 %q", got)
	}
	// Разрыв без ожидания ACK за вторую дельту.
	if _, err := vs.Write([]byte("second!!")); err != nil {
		t.Fatal(err)
	}
	cc1.Close()
	waitFor(t, "detach", func() bool { return vs.State() == VSDetached })
	mux2, _ := tn.dial(t)
	kl.BindMux(mux2)
	waitFor(t, "reattach", func() bool { return vs.State() == VSAttached })
	if got := readFull(t, vs, 8); string(got) != "second!!" {
		t.Fatalf("echo2 %q (дубль или потеря после разрыва)", got)
	}
	vs.Close()
}

// TestCSTNegotiateFallback — нода БЕЗ CST: capability молчит, клиент
// откатывается на legacy, новые CST-потоки не открываются.
func TestCSTNegotiateFallback(t *testing.T) {
	nodePrivB64, nodePubB64, _ := GenerateNodeKey()
	nodePriv, _ := ParseNodePrivKey(nodePrivB64)
	clientB64, clientPubB64, _ := GenerateNodeKey()
	clientPub, _ := base64.RawURLEncoding.DecodeString(clientPubB64)
	nodePub, _ := base64.RawURLEncoding.DecodeString(nodePubB64)
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go io.Copy(c, c)
		}
	}()
	nodeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer nodeLn.Close()
	go func() {
		for {
			c, err := nodeLn.Accept()
			if err != nil {
				return
			}
			go func() {
				sess, _, err := ServerHandshake(c, nodePriv, nil)
				if err != nil {
					return
				}
				conn, err := NewServerConn(c, sess)
				if err != nil {
					return
				}
				ServeMuxWithPolicy(conn, 5*time.Second, NewPolicyEngine(DeclarativePolicy{MaxStreamsPerConn: 256}), nil)
			}()
		}
	}()
	cc, err := DialNode(nodeLn.Addr().String(), nodePubB64, clientB64, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	mux := NewMuxClient(cc)
	kl := NewKnowledgeLayer(clientPub, nodePub, nil)
	kl.negTimeout = 300 * time.Millisecond
	kl.BindMux(mux)
	time.Sleep(700 * time.Millisecond) // дольше negTimeout
	if kl.Active() {
		t.Fatal("CST согласован на legacy-ноде")
	}
	if _, err := kl.OpenFlow(echoLn.Addr().String(), CSTModeTCP); err == nil {
		t.Fatal("OpenFlow без capability должен отклоняться (errVSNoCST)")
	}
	// Legacy smOpen на той же ячейке продолжает работать (обратная совместимость).
	st, err := mux.Open(echoLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write([]byte("ab")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(st, buf); err != nil || string(buf) != "ab" {
		t.Fatalf("legacy echo: %v %q", err, buf)
	}
	st.Close()
}

// TestCSTLegacyOnCSTNode — на CST-ноде legacy-клиент (без knowledge-слоя)
// работает без изменений: smOpen/smData нетронуты, CST-кадры не мешают.
func TestCSTLegacyOnCSTNode(t *testing.T) {
	tn := newCSTTestNode(t, nil)
	defer tn.Close()
	mux, _ := tn.dial(t) // без KnowledgeLayer: чистый legacy
	st, err := mux.Open(tn.echoTarget())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write([]byte("legacy")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 6)
	if _, err := io.ReadFull(st, buf); err != nil || string(buf) != "legacy" {
		t.Fatalf("legacy echo на CST-ноде: %v %q", err, buf)
	}
	st.Close()
}

// TestCSTDowngradeIgnored — после согласования CST поздний hello без флага
// поддержки НЕ понижает слой (anti-downgrade на уровне сессии).
func TestCSTDowngradeIgnored(t *testing.T) {
	tn := newCSTTestNode(t, nil)
	defer tn.Close()
	mux, _ := tn.dial(t)
	kl := tn.newKL()
	kl.BindMux(mux)
	waitFor(t, "negotiate", func() bool { return kl.Active() })
	kl.handlers().onHello(mux, (&CSTHello{Version: 0, Flags: 0}).Encode())
	if !kl.Active() {
		t.Fatal("downgrade: CST сброшен поздним hello")
	}
	vs, err := kl.OpenFlow(tn.echoTarget(), CSTModeTCP)
	if err != nil {
		t.Fatal(err)
	}
	vs.Close()
}

// TestCSTEgressLoss — соединение нода->цель умерло: поток корректно
// закрывается (CSTClose), НИКАКОГО автоматического повтора прикладного
// запроса по новому egress не выполняется.
func TestCSTEgressLoss(t *testing.T) {
	tn := newCSTTestNode(t, nil)
	defer tn.Close()
	mux, _ := tn.dial(t)
	kl := tn.newKL()
	kl.BindMux(mux)
	waitFor(t, "negotiate", func() bool { return kl.Active() })
	vs, err := kl.OpenFlow(tn.echoTarget(), CSTModeTCP)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vs.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if got := readFull(t, vs, 1); string(got) != "x" {
		t.Fatalf("echo %q", got)
	}
	// Рвём egress на стороне «интернета».
	tn.mu.Lock()
	ec := tn.echoConns[0]
	tn.mu.Unlock()
	ec.Close()
	waitFor(t, "flow closed после смерти egress", func() bool { return vs.State() == VSClosed })
	if _, _, _, _, _, ok := tn.reg.flowInfo(vs.ID()); ok {
		t.Fatal("поток остался в реестре после смерти egress")
	}
}
