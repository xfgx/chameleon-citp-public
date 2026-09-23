package main

// listen_test.go — тесты кастомных портов (раунд 6).

import (
	"net"
	"testing"
	"time"
)

// Занятый TCP-порт перебирается на следующий свободный; слушатель живой.
func TestListenTCPFallback(t *testing.T) {
	hold, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()
	busy := hold.Addr().String()

	m := newLayersTestManager(t)
	ln, actual, err := listenTCP(m, busy, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if actual == busy {
		t.Fatalf("порт не перебран: %s", actual)
	}
	c, err := net.DialTimeout("tcp", actual, time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", actual, err)
	}
	_ = c.Close()
}

// Порт 0 отдаётся ОС (возвращается реальный назначенный адрес).
func TestListenPortZero(t *testing.T) {
	m := newLayersTestManager(t)
	ln, actual, err := listenTCP(m, "127.0.0.1:0", "test")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(actual)
	if port == "0" || port == "" {
		t.Fatalf("ОС не назначила порт: %s", actual)
	}
}

// Занятый UDP-порт перебирается на следующий свободный.
func TestListenUDPFallback(t *testing.T) {
	hold, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()
	m := newLayersTestManager(t)
	pc, actual, err := listenUDP(m, hold.LocalAddr().String(), "test-udp")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if actual == hold.LocalAddr().String() {
		t.Fatal("UDP порт не перебран")
	}
}

// Сетка кандидатов: запрошенный порт + 100 следующих, порт 0 — как есть.
func TestAddrCandidatesRange(t *testing.T) {
	cs := addrCandidates("127.0.0.1:65000")
	if len(cs) != 101 {
		t.Fatalf("кандидатов %d, want 101", len(cs))
	}
	if cs[0] != "127.0.0.1:65000" {
		t.Fatalf("первый кандидат %s", cs[0])
	}
	if got := addrCandidates("127.0.0.1:0"); len(got) != 1 {
		t.Fatalf("порт 0: %v", got)
	}
	if got := addrCandidates("bad-addr"); len(got) != 1 || got[0] != "bad-addr" {
		t.Fatalf("невалидный адрес: %v", got)
	}
}
