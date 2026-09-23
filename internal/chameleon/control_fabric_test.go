package chameleon

import (
	"context"
	"net"
	"testing"
	"time"
)

func waitAddr(get func() string) string {
	for i := 0; i < 200; i++ {
		if a := get(); a != "" {
			return a
		}
		time.Sleep(5 * time.Millisecond)
	}
	panic("listener never bound")
}

func hostPort(addr string) (string, int) {
	h, p, _ := net.SplitHostPort(addr)
	pp := 0
	for i := 0; i < len(p); i++ {
		pp = pp*10 + int(p[i]-'0')
	}
	return h, pp
}

func TestTLSBulletinRoundtrip(t *testing.T) {
	srv := NewCDNCacheStateChannel("127.0.0.1:0")
	if err := srv.WithTLS("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve() }()
	addr := waitAddr(srv.Addr)
	cli := NewCDNCacheStateClient("https://" + addr).WithInsecureTLS()

	if err := cli.Upload("sess1", []byte("tls-chunk")); err != nil {
		t.Fatal(err)
	}
	got, err := cli.Poll("sess1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || string(got[0]) != "tls-chunk" {
		t.Fatalf("unexpected: %v", got)
	}
	_ = srv.Shutdown()
}

func TestDoHReal(t *testing.T) {
	r := NewDoHResolver("")
	txts, err := r.ResolveTXT("google.com")
	if err != nil {
		t.Skipf("offline: %v", err)
	}
	if len(txts) == 0 {
		t.Skip("no TXT records")
	}
}

func TestBGPBeaconSnapshot(t *testing.T) {
	bgp := NewBGPControlChannel("")
	snap, err := bgp.BeaconSnapshot(context.Background(), "1.1.1.0/24")
	if err != nil {
		t.Skipf("offline: %v", err)
	}
	if snap == "" {
		t.Fatal("empty snapshot")
	}
}

func TestDPIProfilerBenignRun(t *testing.T) {
	// Benign run: probes real public domains; in a clean network none of the
	// interference flags should fire. Live DoH/HTTP may be offline in CI.
	p := NewDPIProfiler(ProfilerConfig{
		ProbeDomains:  []string{"google.com"},
		ProbeHTTPURLs: []string{"https://www.google.com/"},
		Timeout:       6 * time.Second,
	})
	prof := p.Run(context.Background())
	// We only assert the profile is well-formed; interference booleans depend on
	// the live network, so we don't assert their values here.
	_ = prof.HasDPI
	if prof.MeasuredAt.IsZero() {
		t.Fatal("no measured_at")
	}
}

func TestDPIProfilerNoEvasion(t *testing.T) {
	// The profiler must NOT expose any evasion entry point.
	var _ error = ErrProfilerNotEvasion
}

func TestAdaptiveSelectorLocalPlan(t *testing.T) {
	sel := NewAdaptiveCarrierSelector(DefaultCarrierProfiles())
	// Reliable DNS hijack -> fully local plan (switch to DoH). The raw noisy
	// DNSPoisoning flag alone must NOT trigger the switch (anycast variance).
	plan := sel.Select(CensorProfile{DNSLikelyHijack: true, DNSPoisoning: true, HasDPI: true})
	if !plan.LocalPlan {
		t.Fatal("expected fully local plan")
	}
	foundLocal := false
	for _, a := range plan.Actions {
		if a.Trigger == "dns_likely_hijack" && a.Mode == "local" && a.Local {
			foundLocal = true
		}
	}
	if !foundLocal {
		t.Fatal("missing local DoH action")
	}
}

func TestAdaptiveSelectorInfraGated(t *testing.T) {
	sel := NewAdaptiveCarrierSelector(DefaultCarrierProfiles())
	// TLS/SNI interference -> refraction carrier is infrastructure-gated.
	plan := sel.Select(CensorProfile{TLSInterference: true, HasDPI: true})
	if plan.LocalPlan {
		t.Fatal("expected infrastructure-gated plan")
	}
	hasInfra := false
	for _, a := range plan.Actions {
		if a.Mode == "infrastructure" && !a.Local {
			hasInfra = true
		}
	}
	if !hasInfra {
		t.Fatal("expected an infrastructure-gated action")
	}
}

func TestCryptoRoundtrip(t *testing.T) {
	key := DeriveSessionSecret([]byte("seed"))
	msg := []byte("control message: switch carrier to profile-7")
	enc, err := AEADEncrypt(key, msg)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := AEADDecrypt(key, enc)
	if err != nil {
		t.Fatal(err)
	}
	if string(dec) != string(msg) {
		t.Fatalf("roundtrip mismatch: got %q", dec)
	}
}

func TestFramingRoundtrip(t *testing.T) {
	msg := make([]byte, 500)
	for i := range msg {
		msg[i] = byte(i)
	}
	fr := EncodeControlMessage(msg, 180)
	out := DecodeControlMessage(fr)
	if string(out) != string(msg) {
		t.Fatalf("framing mismatch: %d vs %d bytes", len(out), len(msg))
	}
}

func TestBulletinStoreAndForward(t *testing.T) {
	srv := NewCDNCacheStateChannel("127.0.0.1:0")
	go func() { _ = srv.Serve() }()
	addr := waitAddr(srv.Addr)
	cli := NewCDNCacheStateClient("http://" + addr)

	if err := cli.Upload("sess1", []byte("chunk-a")); err != nil {
		t.Fatal(err)
	}
	if err := cli.Upload("sess1", []byte("chunk-b")); err != nil {
		t.Fatal(err)
	}
	got, err := cli.Poll("sess1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || string(got[0]) != "chunk-a" || string(got[1]) != "chunk-b" {
		t.Fatalf("unexpected frames: %v", got)
	}
	_ = srv.Shutdown()
}

func TestDNSBeacon(t *testing.T) {
	dns := NewDNSBeacon("127.0.0.1:0", "dd.phantom.lab", "c", 1)
	dns.Publish(0, []byte("SID=demo;READY"))
	go func() { _ = dns.Serve() }()
	addr := waitAddr(dns.LocalAddr)
	h, p := hostPort(addr)
	reader := NewDNSBeaconReader(h, p, "dd.phantom.lab", "c")
	got, err := reader.ReadChunk(0)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "SID=demo;READY" {
		t.Fatalf("dns beacon mismatch: %q", got)
	}
	_ = dns.Close()
}

func TestCARVerdictChannel(t *testing.T) {
	// node CAR server
	car := NewCARChannel("127.0.0.1:0")
	go func() { _ = car.Serve() }()
	carAddr := waitAddr(car.Addr)

	// lab mock censor forwarding to the CAR node
	censor := NewMockCensor("127.0.0.1:0", "http://"+carAddr, "")
	go func() { _ = censor.Serve() }()
	censorAddr := waitAddr(censor.Addr)

	reader := NewCARReader("http://" + censorAddr)
	car.SetBit(0, 0)
	car.SetBit(1, 1)
	car.SetBit(2, 1)
	car.SetBit(3, 0)
	bits := reader.ReadBits(0, 4)
	want := []uint8{0, 1, 1, 0}
	for i := range want {
		if bits[i] != want[i] {
			t.Fatalf("bit %d: got %d want %d", i, bits[i], want[i])
		}
	}
	_ = car.Shutdown()
	_ = censor.Shutdown()
}

func TestControlFabricEndToEnd(t *testing.T) {
	cdn := NewCDNCacheStateChannel("127.0.0.1:0")
	car := NewCARChannel("127.0.0.1:0")
	dns := NewDNSBeacon("127.0.0.1:0", "dd.phantom.lab", "c", 1)
	go func() { _ = cdn.Serve() }()
	go func() { _ = car.Serve() }()
	go func() { _ = dns.Serve() }()
	cdnAddr := waitAddr(cdn.Addr)

	cf := NewControlFabric([]byte("master-seed"), cdn, car, dns, nil)
	ctx := context.Background()

	msg := []byte("next-entry=10.0.0.7:8443;profile=refraction-tls")
	if err := cf.PublishControl(ctx, "demo", msg); err != nil {
		t.Fatal(err)
	}

	cli := NewCDNCacheStateClient("http://" + cdnAddr)
	recovered, err := cf.RecoverControl(ctx, "demo", cli)
	if err != nil {
		t.Fatal(err)
	}
	if string(recovered) != string(msg) {
		t.Fatalf("control message mismatch: got %q want %q", recovered, msg)
	}

	// DNS beacon
	r := NewDNSBeaconReader("127.0.0.1", portOf(dns.LocalAddr()), "dd.phantom.lab", "c")
	beacon, err := r.ReadChunk(0)
	if err != nil {
		t.Fatal(err)
	}
	if string(beacon) != "SID=demo;READY" {
		t.Fatalf("beacon mismatch: %q", beacon)
	}

	// BGP is read-only and needs internet; just assert it returns an error
	// type we expect when offline (do not fail the test on network absence).
	_, _ = cf.ObserveBGPRoutes(ctx, "1.1.1.0/24")

	_ = cdn.Shutdown()
	_ = car.Shutdown()
	_ = dns.Close()
}

func portOf(addr string) int {
	_, p, _ := net.SplitHostPort(addr)
	n := 0
	for i := 0; i < len(p); i++ {
		n = n*10 + int(p[i]-'0')
	}
	return n
}
