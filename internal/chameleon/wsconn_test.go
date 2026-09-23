package chameleon

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// WS-носитель (CDN-фронтинг): байтовый поток через адаптер, отказ на неверный
// токен, полное рукопожатие CITP поверх WS (протокол выше не меняется).
func TestWSConnRoundtrip(t *testing.T) {
	const tok = "tok123"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := AcceptWS(w, r, tok)
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c) // echo
	}))
	defer srv.Close()

	base := "ws" + strings.TrimPrefix(srv.URL, "http")

	// Неверный токен: AcceptWS отвечает 404, DialWS обязан получить ошибку.
	if _, err := DialWS(context.Background(), base+"/b/wrong", "", nil); err == nil {
		t.Fatal("неверный токен обязан отклоняться")
	}

	c, err := DialWS(context.Background(), base+"/b/"+tok, "", nil)
	if err != nil {
		t.Fatalf("DialWS: %v", err)
	}
	defer c.Close()

	msg := []byte("ping-cherez-front")
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("эхо не совпало: %q", buf)
	}
}

// Полная сессия CITP поверх WS: рукопожатие + mux + поток, как у TCP-носителя.
func TestWSCarrierFullSession(t *testing.T) {
	privB64, pubB64, err := GenerateNodeKey()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ParseNodePrivKey(privB64)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParseNodePubKey(pubB64)
	if err != nil {
		t.Fatal(err)
	}
	const tok = "fronttok"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := AcceptWS(w, r, tok)
		if err != nil {
			return
		}
		defer c.Close()
		sess, _, err := ServerHandshake(c, priv, nil)
		if err != nil {
			return
		}
		conn, err := NewServerConn(c, sess)
		if err != nil {
			return
		}
		ServeMuxWithPolicy(conn, 5*time.Second, nil, nil)
	}))
	defer srv.Close()

	ckPrivB64, _, _ := GenerateNodeKey()
	ck, _ := ParseNodePrivKey(ckPrivB64)

	raw, err := DialWS(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http")+"/b/"+tok, "", nil)
	if err != nil {
		t.Fatalf("DialWS: %v", err)
	}
	sess, err := ClientHandshake(raw, pub, ck)
	if err != nil {
		t.Fatalf("handshake через WS: %v", err)
	}
	conn, err := NewClientConn(raw, sess)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	mx := NewMuxClient(conn)

	// Эхо-цель: локальный TCP-сервер; нода без политики дозвонится напрямую.
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
			go func() { _, _ = io.Copy(c, c) }()
		}
	}()

	st, err := mx.Open(ln.Addr().String())
	if err != nil {
		t.Fatalf("open через WS-фронт: %v", err)
	}
	defer st.Close()
	if _, err := st.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 2)
	if _, err := io.ReadFull(st, b); err != nil || string(b) != "ok" {
		t.Fatalf("эхо через WS-фронт: %v", err)
	}
}
