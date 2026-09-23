package chameleon

import (
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// Эхо-сервер как «интернет», нода с ServeMux между клиентом и ним.
func TestMuxMultiStream(t *testing.T) {
	// 1. Целевой эхо-сервер (аналог сайта).
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go io.Copy(c, c)
		}
	}()

	// 2. Нода.
	privB64, pubB64, err := GenerateNodeKey()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ParseNodePrivKey(privB64)
	if err != nil {
		t.Fatal(err)
	}
	clientB64, _, err := GenerateNodeKey()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sess, _, err := ServerHandshake(c, priv, nil)
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

	// 3. Клиент: один сеанс, пять параллельных потоков.
	cc, err := DialNode(ln.Addr().String(), pubB64, clientB64, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	mux := NewMuxClient(cc)

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			st, err := mux.Open(echo.Addr().String())
			if err != nil {
				t.Errorf("open %d: %v", n, err)
				return
			}
			defer st.Close()
			msg := []byte(fmt.Sprintf("potok-%d-%s", n, string(make([]byte, 0))))
			payload := make([]byte, 100000)
			copy(payload, msg)
			if _, err := st.Write(payload); err != nil {
				t.Errorf("write %d: %v", n, err)
				return
			}
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(st, got); err != nil {
				t.Errorf("read %d: %v", n, err)
				return
			}
			if string(got[:len(msg)]) != string(msg) {
				t.Errorf("поток %d: данные искажены", n)
			}
		}(i)
	}
	wg.Wait()
}
