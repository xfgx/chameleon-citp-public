// KS endpoint lab: an authenticated, explicit-IP TLS carrier probe.
// It is NOT a VPN or an integrated KS transport. No routes/firewall are edited.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const maxFrame = 4096
const identityName = "ks-endpoint-lab.invalid"

type Config struct {
	Endpoints []string `json:"endpoints"`
	Protected []string `json:"protected_ips"`
	CA        string   `json:"ca_file"`
	Cert      string   `json:"cert_file"`
	Key       string   `json:"key_file"`
	NodePin   string   `json:"node_spki_sha256"`
	TimeoutMS int      `json:"timeout_ms"`
}
type Event struct {
	Event    string `json:"event"`
	Endpoint string `json:"endpoint,omitempty"`
	Sequence int    `json:"sequence,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Time     string `json:"time"`
}

var logMu sync.Mutex

func emit(kind, ep string, seq int, detail string) {
	logMu.Lock()
	defer logMu.Unlock()
	json.NewEncoder(os.Stdout).Encode(Event{kind, ep, seq, detail, time.Now().UTC().Format(time.RFC3339Nano)})
}
func parseEndpoint(s string) (netip.AddrPort, error) {
	a, e := netip.ParseAddrPort(s)
	if e != nil {
		return a, fmt.Errorf("literal IP:port required: %q", s)
	}
	ip := a.Addr().Unmap()
	if a.Port() == 0 || ip.IsUnspecified() || ip.IsMulticast() || ip.Zone() != "" {
		return a, fmt.Errorf("unsafe endpoint: %q", s)
	}
	return netip.AddrPortFrom(ip, a.Port()), nil
}
func validate(c *Config) error {
	if len(c.Endpoints) == 0 {
		return errors.New("empty explicit endpoint pool: fail closed")
	}
	deny := map[netip.Addr]bool{}
	for _, s := range c.Protected {
		a, e := netip.ParseAddr(s)
		if e != nil {
			return fmt.Errorf("invalid protected IP %q", s)
		}
		deny[a.Unmap()] = true
	}
	seen := map[netip.AddrPort]bool{}
	for _, s := range c.Endpoints {
		a, e := parseEndpoint(s)
		if e != nil {
			return e
		}
		if deny[a.Addr()] {
			return errors.New("protected IP in endpoint pool: fail closed")
		}
		if seen[a] {
			return errors.New("duplicate endpoint")
		}
		seen[a] = true
	}
	if c.TimeoutMS < 50 || c.TimeoutMS > 10000 {
		return errors.New("timeout_ms must be 50..10000")
	}
	pin, e := hex.DecodeString(c.NodePin)
	if e != nil || len(pin) != 32 {
		return errors.New("node public-key pin required")
	}
	return nil
}
func loadConfig(path string) (Config, error) {
	var c Config
	b, e := os.ReadFile(path)
	if e != nil {
		return c, e
	}
	if e = json.Unmarshal(b, &c); e != nil {
		return c, e
	}
	for _, p := range []*string{&c.CA, &c.Cert, &c.Key} {
		if !filepath.IsAbs(*p) {
			*p = filepath.Join(filepath.Dir(path), *p)
		}
	}
	return c, validate(&c)
}
func tlsSettings(c Config, server bool) (*tls.Config, error) {
	pair, e := tls.LoadX509KeyPair(c.Cert, c.Key)
	if e != nil {
		return nil, e
	}
	b, e := os.ReadFile(c.CA)
	if e != nil {
		return nil, e
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, errors.New("invalid CA")
	}
	t := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}
	if server {
		t.ClientCAs = pool
		t.ClientAuth = tls.RequireAndVerifyClientCert
	} else {
		t.RootCAs = pool
		t.ServerName = identityName
		t.VerifyConnection = func(s tls.ConnectionState) error {
			if len(s.PeerCertificates) == 0 {
				return errors.New("missing node certificate")
			}
			h := sha256.Sum256(s.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if !strings.EqualFold(hex.EncodeToString(h[:]), c.NodePin) {
				return errors.New("wrong node identity")
			}
			return nil
		}
	}
	return t, nil
}
func sendFrame(w io.Writer, b []byte) error {
	if len(b) == 0 || len(b) > maxFrame {
		return errors.New("invalid frame length")
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(b)))
	if e := writeAll(w, h[:]); e != nil {
		return e
	}
	return writeAll(w, b)
}
func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, e := w.Write(b)
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func readFrame(r io.Reader) ([]byte, error) {
	var h [4]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return nil, e
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || n > maxFrame {
		return nil, errors.New("invalid frame length")
	}
	b := make([]byte, int(n))
	_, e := io.ReadFull(r, b)
	return b, e
}

// Endpoints are pre-provisioned; no DNS lookup, discovered IP, primary-IP
// keepalive, background probe, implicit default or extra fallback exists.
type Pool struct {
	c      Config
	t      *tls.Config
	conn   *tls.Conn
	active string
	next   int
}

func NewPool(c Config) (*Pool, error) {
	if e := validate(&c); e != nil {
		return nil, e
	}
	t, e := tlsSettings(c, false)
	if e != nil {
		return nil, e
	}
	return &Pool{c: c, t: t}, nil
}
func (p *Pool) Close() {
	if p.conn != nil {
		p.conn.Close()
		p.conn = nil
	}
	p.active = ""
}
func (p *Pool) connect(ctx context.Context) error {
	if p.conn != nil {
		return nil
	}
	for i := 0; i < len(p.c.Endpoints); i++ {
		ep := p.c.Endpoints[p.next]
		p.next = (p.next + 1) % len(p.c.Endpoints)
		// Validate again at the socket boundary, including IPv4-mapped IPv6.
		a, e := parseEndpoint(ep)
		if e != nil {
			return e
		}
		for _, s := range p.c.Protected {
			d, _ := netip.ParseAddr(s)
			if a.Addr() == d.Unmap() {
				return errors.New("protected socket destination")
			}
		}
		emit("dial", ep, 0, "")
		d := &net.Dialer{Timeout: time.Duration(p.c.TimeoutMS) * time.Millisecond}
		raw, e := d.DialContext(ctx, "tcp", a.String())
		if e != nil {
			emit("dial_failed", ep, 0, e.Error())
			continue
		}
		tc := tls.Client(raw, p.t)
		tc.SetDeadline(time.Now().Add(time.Duration(p.c.TimeoutMS) * time.Millisecond))
		e = tc.HandshakeContext(ctx)
		if e != nil {
			tc.Close()
			emit("authentication_failed", ep, 0, e.Error())
			continue
		}
		p.conn = tc
		p.active = ep
		emit("connected", ep, 0, "TLS1.3, verified node key")
		return nil
	}
	return errors.New("all explicit endpoints unavailable: fail closed")
}

// Exchange does not replay an uncertain application operation after failure.
// The next NEW request may reconnect. A production KS adapter must preserve
// datagram/replay semantics and implement queues/backpressure independently.
func (p *Pool) Exchange(ctx context.Context, b []byte) ([]byte, error) {
	if len(b) == 0 || len(b) > maxFrame {
		return nil, errors.New("invalid frame length")
	}
	if e := p.connect(ctx); e != nil {
		return nil, e
	}
	p.conn.SetDeadline(time.Now().Add(time.Duration(p.c.TimeoutMS) * time.Millisecond))
	if e := sendFrame(p.conn, b); e != nil {
		p.Close()
		return nil, fmt.Errorf("request not retried: %w", e)
	}
	q, e := readFrame(p.conn)
	if e != nil {
		p.Close()
		return nil, fmt.Errorf("delivery uncertain, not replayed: %w", e)
	}
	return q, nil
}
func serve(ctx context.Context, c Config, dropFirst int) error {
	if e := validate(&c); e != nil {
		return e
	}
	tc, e := tlsSettings(c, true)
	if e != nil {
		return e
	}
	listeners := []net.Listener{}
	defer func() {
		for _, l := range listeners {
			l.Close()
		}
	}()
	for _, ep := range c.Endpoints {
		a, _ := parseEndpoint(ep)
		l, e := net.Listen("tcp", a.String())
		if e != nil {
			return e
		}
		listeners = append(listeners, l)
	}
	var wg sync.WaitGroup
	var total atomic.Int64
	slots := make(chan struct{}, 16)
	for index, l := range listeners {
		wg.Add(1)
		go func(index int, l net.Listener) {
			defer wg.Done()
			var n atomic.Int64
			for {
				raw, e := l.Accept()
				if e != nil {
					return
				}
				select {
				case slots <- struct{}{}:
				default:
					raw.Close()
					continue
				}
				wg.Add(1)
				go func(raw net.Conn) {
					defer wg.Done()
					defer func() { <-slots }()
					defer raw.Close()
					conn := tls.Server(raw, tc)
					conn.SetDeadline(time.Now().Add(3 * time.Second))
					if e := conn.HandshakeContext(ctx); e != nil {
						emit("client_auth_failed", c.Endpoints[index], 0, "")
						return
					}
					for {
						conn.SetDeadline(time.Now().Add(3 * time.Second))
						b, e := readFrame(conn)
						if e != nil {
							return
						}
						if e = sendFrame(conn, b); e != nil {
							return
						}
						total.Add(1)
						emit("echo", c.Endpoints[index], int(total.Load()), "")
						if index == 0 && dropFirst > 0 && n.Add(1) >= int64(dropFirst) {
							l.Close()
							emit("fault_listener_closed", c.Endpoints[index], 0, "test fault; not an ISP block")
							return
						}
					}
				}(raw)
			}
		}(index, l)
	}
	emit("ready", "", 0, fmt.Sprintf("%d exact-IP listeners", len(listeners)))
	<-ctx.Done()
	for _, l := range listeners {
		l.Close()
	}
	wg.Wait()
	emit("server_stopped", "", int(total.Load()), "")
	return nil
}
func probe(c Config, count int, interval time.Duration) error {
	p, e := NewPool(c)
	if e != nil {
		return e
	}
	defer p.Close()
	ok := 0
	for i := 1; i <= count; i++ {
		b := make([]byte, 96)
		rand.Read(b)
		binary.BigEndian.PutUint32(b[:4], uint32(i))
		q, e := p.Exchange(context.Background(), b)
		if e != nil {
			emit("probe_failed", "", i, e.Error())
		} else if string(q) != string(b) {
			emit("probe_failed", p.active, i, "echo mismatch")
		} else {
			ok++
			emit("probe_ok", p.active, i, "")
		}
		if i < count {
			time.Sleep(interval)
		}
	}
	emit("summary", "", count, fmt.Sprintf("success=%d attempted=%d", ok, count))
	if ok != count {
		return errors.New("one or more probes failed")
	}
	return nil
}
func serial() *big.Int { n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120)); return n }
func fixture(dir string) error {
	if _, e := os.Stat(dir); e == nil {
		return errors.New("refuse to overwrite existing credential directory")
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	now := time.Now()
	cak, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return e
	}
	ca := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "KS isolated lab CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	cab, e := x509.CreateCertificate(rand.Reader, ca, ca, &cak.PublicKey, cak)
	if e != nil {
		return e
	}
	os.WriteFile(filepath.Join(dir, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cab}), 0600)
	pin := ""
	for _, role := range []string{"server", "client"} {
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return e
		}
		usage := x509.ExtKeyUsageClientAuth
		if role == "server" {
			usage = x509.ExtKeyUsageServerAuth
		}
		t := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "KS lab " + role}, DNSNames: []string{identityName}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		der, e := x509.CreateCertificate(rand.Reader, t, ca, &k.PublicKey, cak)
		if e != nil {
			return e
		}
		kb, e := x509.MarshalPKCS8PrivateKey(k)
		if e != nil {
			return e
		}
		if e = os.WriteFile(filepath.Join(dir, role+".pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); e != nil {
			return e
		}
		if e = os.WriteFile(filepath.Join(dir, role+".key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0600); e != nil {
			return e
		}
		if role == "server" {
			cert, _ := x509.ParseCertificate(der)
			h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			pin = hex.EncodeToString(h[:])
		}
	}
	for _, role := range []string{"server", "client"} {
		c := Config{Endpoints: []string{"127.0.0.2:24443", "127.0.0.3:24443"}, Protected: []string{"127.0.0.1"}, CA: "ca.pem", Cert: role + ".pem", Key: role + ".key", NodePin: pin, TimeoutMS: 1200}
		b, _ := json.MarshalIndent(c, "", "  ")
		if e = os.WriteFile(filepath.Join(dir, role+".json"), b, 0600); e != nil {
			return e
		}
	}
	emit("fixture_created", "", 0, "one-day lab credentials only; CA private key not saved")
	return nil
}
func main() {
	mode := flag.String("mode", "probe", "init|server|probe")
	config := flag.String("config", "client.json", "explicit config file")
	dir := flag.String("dir", "credentials", "new lab credential directory")
	count := flag.Int("count", 12, "new probe requests (1..100)")
	duration := flag.Duration("duration", 90*time.Second, "server lifetime (max 10m)")
	interval := flag.Duration("interval", 100*time.Millisecond, "delay between probes")
	drop := flag.Int("fault-close-first-after", 0, "lab only: close first listener after N echoes")
	flag.Parse()
	var e error
	if *mode == "init" {
		e = fixture(*dir)
	} else {
		var c Config
		c, e = loadConfig(*config)
		if e == nil {
			switch *mode {
			case "server":
				if *duration <= 0 || *duration > 10*time.Minute {
					e = errors.New("duration must be 0..10m")
				} else {
					ctx, cancel := context.WithTimeout(context.Background(), *duration)
					defer cancel()
					e = serve(ctx, c, *drop)
				}
			case "probe":
				if *count < 1 || *count > 100 {
					e = errors.New("count must be 1..100")
				} else {
					e = probe(c, *count, *interval)
				}
			default:
				e = errors.New("unknown mode")
			}
		}
	}
	if e != nil {
		emit("fatal", "", 0, e.Error())
		os.Exit(2)
	}
}
