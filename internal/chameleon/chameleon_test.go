package chameleon

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"net"
	"sync"
	"testing"
	"time"
)

// tapConn записывает всё, что клиент отправляет в провод после рукопожатия.
type tapConn struct {
	net.Conn
	mu  *sync.Mutex
	buf *bytes.Buffer
}

func (t *tapConn) Write(p []byte) (int, error) {
	t.mu.Lock()
	t.buf.Write(p)
	t.mu.Unlock()
	return t.Conn.Write(p)
}

// testNodeKeys — пара ключей ноды для in-process тестов.
func testNodeKeys(t *testing.T) (priv *ecdh.PrivateKey, pub *ecdh.PublicKey) {
	t.Helper()
	privB64, pubB64, err := GenerateNodeKey()
	if err != nil {
		t.Fatal(err)
	}
	priv, err = ParseNodePrivKey(privB64)
	if err != nil {
		t.Fatal(err)
	}
	pub, err = ParseNodePubKey(pubB64)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

// testClientKey — персональный ключ «устройства» для тестов.
func testClientKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	privB64, _, err := GenerateNodeKey()
	if err != nil {
		t.Fatal(err)
	}
	priv, err2 := ParseNodePrivKey(privB64)
	if err2 != nil {
		t.Fatal(err2)
	}
	return priv
}

// runSession поднимает in-process сервер, проводит рукопожатие, отправляет
// сообщение и возвращает ответ эха + сырые байты кадров "на проводе".
func runSession(t *testing.T, msg []byte) (reply []byte, wire []byte) {
	t.Helper()
	priv, pub := testNodeKeys(t)
	clientKey := testClientKey(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		sc, err := ln.Accept()
		if err != nil {
			return
		}
		sess, _, err := ServerHandshake(sc, priv, nil)
		if err != nil {
			t.Errorf("server handshake: %v", err)
			return
		}
		conn, err := NewServerConn(sc, sess)
		if err != nil {
			t.Errorf("server conn: %v", err)
			return
		}
		m, err := conn.ReadMessage()
		if err != nil {
			t.Errorf("server read: %v", err)
			return
		}
		if err := conn.WriteMessage(append([]byte("echo:"), m...)); err != nil {
			t.Errorf("server write: %v", err)
		}
	}()

	cc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	sess, err := ClientHandshake(cc, pub, clientKey)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	// Подключаем "анализатор трафика" ПОСЛЕ рукопожатия — смотрим только кадры.
	var mu sync.Mutex
	var buf bytes.Buffer
	conn, err := NewClientConn(&tapConn{Conn: cc, mu: &mu, buf: &buf}, sess)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.WriteMessage(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	reply, err = conn.ReadMessage()
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	<-done
	mu.Lock()
	wire = append([]byte{}, buf.Bytes()...)
	mu.Unlock()
	return reply, wire
}

func TestEchoWorks(t *testing.T) {
	reply, _ := runSession(t, []byte("sekretnyj payload"))
	if string(reply) != "echo:sekretnyj payload" {
		t.Fatalf("неверное эхо: %q", reply)
	}
}

func TestNoFixedSignature(t *testing.T) {
	msg := []byte("odin i tot zhe payload v oboikh seansakh")
	_, wire1 := runSession(t, msg)
	_, wire2 := runSession(t, msg)

	if len(wire1) == len(wire2) {
		t.Logf("предупреждение: длины совпали (%d) — допустимо, но редко", len(wire1))
	}
	// Первые 16 байт кадра (maskedLen + начало мусорного заголовка)
	// не должны совпадать между сеансами.
	if bytes.Equal(wire1[:16], wire2[:16]) {
		t.Fatal("сигнатура повторилась: DRBG не меняет маску между сеансами")
	}
	t.Logf("сеанс 1, первые 48 байт провода:\n%s", hex.Dump(wire1[:48]))
	t.Logf("сеанс 2, первые 48 байт провода:\n%s", hex.Dump(wire2[:48]))
}

func TestDesyncDetection(t *testing.T) {
	priv, _ := testNodeKeys(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	// "Враждебный зонд": шлём мусор вместо рукопожатия.
	go func() {
		cc, err := net.Dial("tcp", ln.Addr().String())
		if err == nil {
			cc.Write([]byte("GET / HTTP/1.1\r\nHost: ya.ru\r\n\r\n"))
			cc.Close()
		}
	}()
	sc, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	if _, _, err := ServerHandshake(sc, priv, nil); err == nil {
		t.Fatal("рукопожатие с мусором не должно проходить")
	}
}

// TestProbeGetsSilence: зонд из 72+ случайных байт (ровно размер client
// hello) получает ErrAuth и НИ БАЙТА ответа — нода неотличима от мёртвой.
func TestProbeGetsSilence(t *testing.T) {
	priv, _ := testNodeKeys(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		sc, err := ln.Accept()
		if err != nil {
			return
		}
		defer sc.Close()
		if _, _, err := ServerHandshake(sc, priv, nil); err != ErrAuth {
			t.Errorf("ожидался ErrAuth, получено: %v", err)
		}
		// Продакшен-путь: Blackhole молча поглощает. Здесь просто не пишем.
	}()
	cc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	probe := make([]byte, clientHelloLen)
	rand.Read(probe)
	if _, err := cc.Write(probe); err != nil {
		t.Fatal(err)
	}
	cc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := cc.Read(make([]byte, 1))
	if n != 0 || err == nil {
		t.Fatalf("нода ответила зонду: прочитано %d байт, err=%v", n, err)
	}
}

// TestWrongKeyGetsSilence: клиент с ЧУЖИМ публичным ключом (настоящий
// активный зонд, знающий формат протокола) получает то же молчание.
func TestWrongKeyGetsSilence(t *testing.T) {
	priv, _ := testNodeKeys(t)
	_, wrongPub := testNodeKeys(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		sc, err := ln.Accept()
		if err != nil {
			return
		}
		defer sc.Close()
		if _, _, err := ServerHandshake(sc, priv, nil); err != ErrAuth {
			t.Errorf("ожидался ErrAuth, получено: %v", err)
		}
	}()
	cc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	if _, err := ClientHandshake(cc, wrongPub, testClientKey(t)); err == nil {
		t.Fatal("клиент с чужим ключом не должен проходить")
	}
}
