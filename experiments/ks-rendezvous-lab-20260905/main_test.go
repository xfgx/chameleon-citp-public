package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func baseConfig() Config {
	return Config{Endpoints: []string{"127.0.0.2:24443"}, Protected: []string{"127.0.0.1"}, NodePin: strings.Repeat("a", 64), TimeoutMS: 200}
}
func TestPolicy(t *testing.T) {
	tests := []struct {
		name      string
		eps, deny []string
		wantOK    bool
	}{
		{"explicit_alias", []string{"127.0.0.2:24443"}, []string{"127.0.0.1"}, true},
		{"protected_primary", []string{"127.0.0.1:24443"}, []string{"127.0.0.1"}, false},
		{"mapped_protected", []string{"[::ffff:127.0.0.1]:24443"}, []string{"127.0.0.1"}, false},
		{"mapped_deny", []string{"127.0.0.1:24443"}, []string{"::ffff:127.0.0.1"}, false},
		{"no_dns", []string{"example.com:443"}, []string{"127.0.0.1"}, false},
		{"no_wildcard", []string{"0.0.0.0:443"}, []string{"127.0.0.1"}, false},
		{"no_multicast", []string{"224.0.0.1:443"}, []string{"127.0.0.1"}, false},
		{"no_empty_pool", nil, []string{"127.0.0.1"}, false},
		{"no_duplicates", []string{"127.0.0.2:443", "[::ffff:127.0.0.2]:443"}, []string{"127.0.0.1"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := baseConfig()
			c.Endpoints = tt.eps
			c.Protected = tt.deny
			if (validate(&c) == nil) != tt.wantOK {
				t.Fatal("unexpected policy result")
			}
		})
	}
}

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > 2 {
		p = p[:2]
	}
	return w.Buffer.Write(p)
}
func TestFraming(t *testing.T) {
	w := &shortWriter{}
	p := bytes.Repeat([]byte{7}, 128)
	if e := sendFrame(w, p); e != nil {
		t.Fatal(e)
	}
	q, e := readFrame(&w.Buffer)
	if e != nil || !bytes.Equal(p, q) {
		t.Fatal("partial writes broke framing")
	}
	for _, n := range []uint32{0, maxFrame + 1, 0xffffffff} {
		var h [4]byte
		binary.BigEndian.PutUint32(h[:], n)
		if _, e := readFrame(bytes.NewReader(h[:])); e == nil {
			t.Fatal("bad length accepted")
		}
	}
	if e := sendFrame(io.Discard, make([]byte, maxFrame+1)); e == nil {
		t.Fatal("oversized send accepted")
	}
}
func setup(t *testing.T) (Config, Config) {
	t.Helper()
	d := filepath.Join(t.TempDir(), "new")
	if e := fixture(d); e != nil {
		t.Fatal(e)
	}
	s, e := loadConfig(filepath.Join(d, "server.json"))
	if e != nil {
		t.Fatal(e)
	}
	c, e := loadConfig(filepath.Join(d, "client.json"))
	if e != nil {
		t.Fatal(e)
	}
	l, e := net.Listen("tcp", "127.0.0.2:0")
	if e != nil {
		t.Fatal(e)
	}
	_, port, _ := net.SplitHostPort(l.Addr().String())
	l.Close()
	s.Endpoints = []string{net.JoinHostPort("127.0.0.2", port), net.JoinHostPort("127.0.0.3", port)}
	c.Endpoints = append([]string{}, s.Endpoints...)
	s.TimeoutMS = 300
	c.TimeoutMS = 300
	return s, c
}
func startServer(t *testing.T, s Config, drop int) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, s, drop) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, e := net.DialTimeout("tcp", s.Endpoints[0], 20*time.Millisecond)
		if e == nil {
			c.Close()
			return func() {
				cancel()
				select {
				case e := <-done:
					if e != nil {
						t.Error(e)
					}
				case <-time.After(4 * time.Second):
					t.Error("server cleanup timeout")
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	t.Fatal("server not ready")
	return func() {}
}
func TestRealSocketsFailover(t *testing.T) {
	s, c := setup(t)
	stop := startServer(t, s, 2)
	defer stop()
	p, e := NewPool(c)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	for i := 0; i < 2; i++ {
		q, e := p.Exchange(context.Background(), []byte("first"))
		if e != nil || string(q) != "first" {
			t.Fatalf("first endpoint: %v", e)
		}
	}
	if _, e := p.Exchange(context.Background(), []byte("uncertain")); e == nil {
		t.Fatal("closed connection unexpectedly accepted")
	}
	q, e := p.Exchange(context.Background(), []byte("next-new-request"))
	if e != nil || string(q) != "next-new-request" || p.active != c.Endpoints[1] {
		t.Fatalf("failover did not reach second IP: %s %v", p.active, e)
	}
}
func TestWrongIdentityAndClient(t *testing.T) {
	s, c := setup(t)
	stop := startServer(t, s, 0)
	defer stop()
	wrong := c
	wrong.NodePin = strings.Repeat("0", 64)
	p, e := NewPool(wrong)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = p.Exchange(context.Background(), []byte("test")); e == nil {
		t.Fatal("wrong server key accepted")
	}
	p.Close()
	d := filepath.Join(t.TempDir(), "foreign")
	if e = fixture(d); e != nil {
		t.Fatal(e)
	}
	foreign := c
	foreign.Cert = filepath.Join(d, "client.pem")
	foreign.Key = filepath.Join(d, "client.key")
	p, e = NewPool(foreign)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	if _, e = p.Exchange(context.Background(), []byte("test")); e == nil {
		t.Fatal("untrusted client accepted")
	}
}
func TestAllDownAndNoDiscovery(t *testing.T) {
	_, c := setup(t)
	p, e := NewPool(c)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	if _, e = p.Exchange(context.Background(), []byte("test")); e == nil || !strings.Contains(e.Error(), "fail closed") {
		t.Fatal("must fail closed")
	}
	if p.conn != nil {
		t.Fatal("unexpected connection")
	}
}
func TestFixtureNeverOverwrites(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "sentinel"), []byte("keep"), 0600)
	if e := fixture(d); e == nil {
		t.Fatal("overwrote existing directory")
	}
	b, _ := os.ReadFile(filepath.Join(d, "sentinel"))
	if string(b) != "keep" {
		t.Fatal("sentinel modified")
	}
}
func TestInvalidFrameDoesNotDial(t *testing.T) {
	_, c := setup(t)
	p, e := NewPool(c)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	_, e = p.Exchange(context.Background(), nil)
	if e == nil || p.conn != nil {
		t.Fatal("invalid frame attempted a connection")
	}
	if errors.Is(e, io.EOF) {
		t.Fatal("wrong error")
	}
}
