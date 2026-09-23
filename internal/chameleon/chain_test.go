package chameleon

// chain_test.go — каскад нода→нода: end-to-end на loopback (две тестовые
// ноды), fail-closed при мёртвом аплинке, переподключение, direct-список.

import (
	"crypto/ecdh"
	"encoding/base64"
	"io"
	"net"
	"testing"
	"time"
)

// startChainEcho — TCP-эхо цель.
func startChainEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

// testNode — тестовая нода: слушатель + рукопожатие + mux (с каскадом или без).
type testNode struct {
	ln        net.Listener
	priv      *ecdh.PrivateKey
	pub       *ecdh.PublicKey
	privB64   string
	pubB64    string
	egress    func(string) (net.Conn, error)
	egressUDP func(string) (net.Conn, error)
	policy    *PolicyEngine
}

func startTestNode(t *testing.T, listenAddr string, privB64 string, policy *PolicyEngine, egress, egressUDP func(string) (net.Conn, error)) *testNode {
	t.Helper()
	var err error
	var pubB64 string
	if privB64 == "" {
		privB64, pubB64, err = GenerateNodeKey()
		if err != nil {
			t.Fatal(err)
		}
	} else {
		p, err := ParseNodePrivKey(privB64)
		if err != nil {
			t.Fatal(err)
		}
		pubB64 = base64.RawURLEncoding.EncodeToString(p.PublicKey().Bytes())
	}
	priv, err := ParseNodePrivKey(privB64)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParseNodePubKey(pubB64)
	if err != nil {
		t.Fatal(err)
	}
	if listenAddr == "" {
		listenAddr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		t.Fatal(err)
	}
	n := &testNode{ln: ln, priv: priv, pub: pub, privB64: privB64, pubB64: pubB64, policy: policy, egress: egress, egressUDP: egressUDP}
	go n.serve()
	return n
}

func (n *testNode) serve() {
	for {
		c, err := n.ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			sess, _, err := ServerHandshake(c, n.priv, nil)
			if err != nil {
				return
			}
			conn, err := NewServerConn(c, sess)
			if err != nil {
				return
			}
			if n.egress != nil {
				ServeMuxWithEgress(conn, 5*time.Second, n.policy, nil, n.egress, n.egressUDP)
				return
			}
			ServeMuxWithPolicy(conn, 5*time.Second, n.policy, nil)
		}()
	}
}

// restart поднимает слушатель заново на том же адресе с теми же ключами.
func (n *testNode) restart(t *testing.T) {
	t.Helper()
	addr := n.ln.Addr().String()
	_ = n.ln.Close()
	for i := 0; i < 50; i++ {
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			n.ln = ln
			go n.serve()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("restart: не смог переоткрыть слушатель")
}

func (n *testNode) addr() string { return n.ln.Addr().String() }
func (n *testNode) close()       { _ = n.ln.Close() }

// clientMuxTo — клиентское рукопожатие + mux к ноде.
func clientMuxTo(t *testing.T, addr, pubB64 string) (*Mux, net.Conn) {
	t.Helper()
	pub, err := ParseNodePubKey(pubB64)
	if err != nil {
		t.Fatal(err)
	}
	privB64, _, err := GenerateNodeKey()
	if err != nil {
		t.Fatal(err)
	}
	ck, err := ParseNodePrivKey(privB64)
	if err != nil {
		t.Fatal(err)
	}
	cc, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := ClientHandshake(cc, pub, ck)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := NewClientConn(cc, sess)
	if err != nil {
		t.Fatal(err)
	}
	return NewMuxClient(conn), cc
}

// Каскад end-to-end: клиент → вход (цепочка) → выход → эхо. Проверяем и
// IP-цель, и доменную (домен обязан резолвиться на ВЫХОДЕ, а не на входе).
func TestChainEndToEnd(t *testing.T) {
	// The loopback fixture must be explicitly resolvable; production rejects it.
	previous := AllowPrivateResolution
	AllowPrivateResolution = true
	t.Cleanup(func() { AllowPrivateResolution = previous })
	echo := startChainEcho(t)
	exit := startTestNode(t, "", "", nil, nil, nil)
	defer exit.close()

	ckPriv, _, err := GenerateNodeKey()
	if err != nil {
		t.Fatal(err)
	}
	ck, err := ParseNodePrivKey(ckPriv)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := NewUpstreamChain(exit.addr(), exit.pubB64, ck, nil)
	if err != nil {
		t.Fatal(err)
	}
	chain.Start()
	defer chain.Close()

	entry := startTestNode(t, "", "", nil, chain.Dial, chain.DialUDP)
	defer entry.close()

	mx, cc := clientMuxTo(t, entry.addr(), entry.pubB64)
	defer cc.Close()

	// IP-цель через цепочку.
	st, err := mx.Open(echo)
	if err != nil {
		t.Fatalf("open по IP через цепочку: %v", err)
	}
	if _, err := st.Write([]byte("ping-over-chain")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := st.Read(buf)
	if err != nil || string(buf[:n]) != "ping-over-chain" {
		t.Fatalf("эхо через цепочку: n=%d err=%v", n, err)
	}
	_ = st.Close()

	// Доменная цель: RESOLVE на входе отключён → legacy open с доменом →
	// резолвит выходная нода.
	if _, err := mx.Resolve("localhost"); err == nil {
		t.Fatal("RESOLVE на входной ноде каскада должен быть отключён")
	}
	_, port, _ := net.SplitHostPort(echo)
	st2, err := mx.Open("localhost:" + port)
	if err != nil {
		t.Fatalf("open по домену через цепочку: %v", err)
	}
	if _, err := st2.Write([]byte("domain-via-exit")); err != nil {
		t.Fatal(err)
	}
	n, err = st2.Read(buf)
	if err != nil || string(buf[:n]) != "domain-via-exit" {
		t.Fatalf("доменное эхо через цепочку: n=%d err=%v", n, err)
	}
	_ = st2.Close()
}

// Fail-closed: аплинк мёртв → открытие потока ошибкой, никакого прямого
// дозвона с IP входной ноды.
func TestChainFailClosed(t *testing.T) {
	ckPriv, _, _ := GenerateNodeKey()
	ck, _ := ParseNodePrivKey(ckPriv)
	// Аплинк на мёртвый адрес.
	chain, err := NewUpstreamChain("127.0.0.1:1", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ck, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Start не вызываем: проверяем синхронный путь.
	if _, err := chain.Dial("203.0.113.1:443"); err == nil {
		t.Fatal("при мёртвом аплинке Dial обязан вернуть ошибку (fail-closed)")
	}
	_ = chain.Close()

	entry := startTestNode(t, "", "", nil, chain.Dial, chain.DialUDP)
	defer entry.close()
	mx, cc := clientMuxTo(t, entry.addr(), entry.pubB64)
	defer cc.Close()
	if _, err := mx.Open("203.0.113.1:443"); err == nil {
		t.Fatal("open через мёртвый каскад обязан вернуть ошибку")
	}
}

// Переподключение: выходная нода умерла и поднялась снова — цепочка
// восстанавливается сама (maintain-контур).
func TestChainReconnect(t *testing.T) {
	echo := startChainEcho(t)
	exit := startTestNode(t, "", "", nil, nil, nil)

	ckPriv, _, _ := GenerateNodeKey()
	ck, _ := ParseNodePrivKey(ckPriv)
	chain, err := NewUpstreamChain(exit.addr(), exit.pubB64, ck, nil)
	if err != nil {
		t.Fatal(err)
	}
	chain.Start()
	defer chain.Close()

	// Аплинк поднялся.
	var st net.Conn
	for i := 0; i < 50; i++ {
		st, err = chain.Dial(echo)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("аплинк не поднялся: %v", err)
	}
	_ = st.Close()

	// Выходная нода падает и встаёт с теми же ключами на том же адресе.
	exit.close()
	time.Sleep(100 * time.Millisecond)
	exit2 := startTestNode(t, exit.addr(), exit.privB64, nil, nil, nil)
	defer exit2.close()

	// Цепочка обязана сама переподключиться и снова нести трафик.
	ok := false
	for i := 0; i < 100; i++ {
		st, err := chain.Dial(echo)
		if err == nil {
			if _, err := st.Write([]byte("x")); err == nil {
				b := make([]byte, 1)
				if _, err := st.Read(b); err == nil && b[0] == 'x' {
					ok = true
				}
			}
			_ = st.Close()
			if ok {
				break
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !ok {
		t.Fatal("цепочка не восстановилась после рестарта выходной ноды")
	}
}

// Direct-список: домены из него идут напрямую, остальные — в цепочку.
func TestChainDirectList(t *testing.T) {
	ckPriv, _, _ := GenerateNodeKey()
	ck, _ := ParseNodePrivKey(ckPriv)
	chain, err := NewUpstreamChain("127.0.0.1:1", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ck, []string{"ya.ru", ".gosuslugi.ru"})
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Close()
	for _, tc := range []struct {
		host   string
		direct bool
	}{
		{"ya.ru", true},
		{"www.ya.ru", true},
		{"id.gosuslugi.ru", true},
		{"google.com", false},
	} {
		if got := chain.matchDirect(tc.host); got != tc.direct {
			t.Fatalf("matchDirect(%q)=%v, want %v", tc.host, got, tc.direct)
		}
	}
}

// Входная нода с дефолтной политикой (RequireDNSBinding) в режиме каскада:
// доменные цели проходят без ResolutionObject (их резолвит выход), а IP-цели
// проверяются политикой входа как обычно (loopback запрещён). Без каскада та
// же политика домен отклоняет — негативный контроль в конце теста.
func TestChainEntryPolicyDNSBinding(t *testing.T) {
	// Only the permissive exit fixture may resolve loopback; entry policy stays strict.
	previous := AllowPrivateResolution
	AllowPrivateResolution = true
	t.Cleanup(func() { AllowPrivateResolution = previous })
	echo := startChainEcho(t)

	// Выходная нода без политики выдаёт canonical ResolutionObject для
	// loopback-фикстуры и открывает DNS-bound поток; legacy fallback не нужен.
	exit := startTestNode(t, "", "", nil, nil, nil)
	defer exit.close()

	ckPriv, _, _ := GenerateNodeKey()
	ck, _ := ParseNodePrivKey(ckPriv)
	chain, err := NewUpstreamChain(exit.addr(), exit.pubB64, ck, nil)
	if err != nil {
		t.Fatal(err)
	}
	chain.Start()
	defer chain.Close()

	entry := startTestNode(t, "", "", NewPolicyEngine(DefaultPolicy()), chain.Dial, chain.DialUDP)
	defer entry.close()

	mx, cc := clientMuxTo(t, entry.addr(), entry.pubB64)
	defer cc.Close()

	_, port, _ := net.SplitHostPort(echo)

	// Домен без ResolutionObject: вход отпускает в цепочку, выход резолвит.
	st, err := mx.Open("localhost:" + port)
	if err != nil {
		t.Fatalf("домен через каскад с RequireDNSBinding: %v", err)
	}
	if _, err := st.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 2)
	if _, err := st.Read(b); err != nil || string(b) != "ok" {
		t.Fatalf("эхо через каскад: %v", err)
	}
	_ = st.Close()

	// IP-цель loopback: политика входа обязана отказать даже при каскаде.
	if _, err := mx.Open(echo); err == nil {
		t.Fatal("loopback IP обязан отклоняться политикой входной ноды")
	}

	// Негативный контроль: та же дефолтная политика БЕЗ каскада — домен без
	// ResolutionObject отклоняется (поведение вне цепочки не изменилось).
	plain := startTestNode(t, "", "", NewPolicyEngine(DefaultPolicy()), nil, nil)
	defer plain.close()
	mx2, cc2 := clientMuxTo(t, plain.addr(), plain.pubB64)
	defer cc2.Close()
	if _, err := mx2.Open("localhost:" + port); err == nil {
		t.Fatal("без каскада домен без ResolutionObject обязан отклоняться")
	}
}
