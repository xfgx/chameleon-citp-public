package main

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func rvFixture() (Schedule, []byte) {
	return Schedule{Prefix: "2001:db8:300::/64", FullPrefixAuthorized: true, NodeID: strings.Repeat("a", 64), StepSeconds: 30, Port: 24443, Protected: []string{"2001:db8:300::193"}}, []byte("0123456789abcdef0123456789abcdef")
}
func TestRendezvousDeterminismAndWindow(t *testing.T) {
	c, k := rvFixture()
	a, e := planAddresses(c, k, 3000)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := planAddresses(c, k, 3029)
	if !reflect.DeepEqual(a, b) {
		t.Fatal("not stable in epoch")
	}
	next, _ := planAddresses(c, k, 3030)
	if a.Endpoints[0] != next.Endpoints[1] || a.Endpoints[2] != next.Endpoints[0] {
		t.Fatal("window mismatch")
	}
	n := netip.MustParsePrefix(c.Prefix)
	for _, ep := range a.Endpoints {
		ip := netip.MustParseAddrPort(ep).Addr()
		if !n.Contains(ip) {
			t.Fatal("escaped prefix")
		}
	}
}
func TestRendezvousDomainSeparation(t *testing.T) {
	c, k := rvFixture()
	a, _ := planAddresses(c, k, 3000)
	variants := []Schedule{c, c, c}
	variants[0].NodeID = strings.Repeat("b", 64)
	variants[1].Port++
	variants[2].StepSeconds = 60
	for _, v := range variants {
		b, e := planAddresses(v, k, 3000)
		if e != nil || b.Endpoints[0] == a.Endpoints[0] {
			t.Fatal("context not separated", e)
		}
	}
	k[0] ^= 1
	b, _ := planAddresses(c, k, 3000)
	if b.Endpoints[0] == a.Endpoints[0] {
		t.Fatal("key ignored")
	}
}
func TestRendezvousRejectsUnsafePlans(t *testing.T) {
	c, k := rvFixture()
	a, _ := planAddresses(c, k, 3000)
	variants := []Schedule{c, c, c, c, c, c}
	variants[0].FullPrefixAuthorized = false
	variants[1].Prefix = "2001:db8:300::1/64"
	variants[2].Prefix = "2001:db8::/48"
	variants[3].Prefix = "fe80::/64"
	variants[4].Protected = []string{netip.MustParseAddrPort(a.Endpoints[0]).Addr().String()}
	variants[5].Pool = []string{"192.0.2.1:443", "192.0.2.2:443"}
	for i, v := range variants {
		if _, e := planAddresses(v, k, 3000); e == nil {
			t.Fatalf("unsafe case %d accepted", i)
		}
	}
	if _, e := planAddresses(c, k[:31], 3000); e == nil {
		t.Fatal("short key")
	}
	if _, e := planAddresses(c, k, -1); e == nil {
		t.Fatal("negative time")
	}
}
func TestRendezvousExplicitPool(t *testing.T) {
	c, k := rvFixture()
	c.Prefix = ""
	c.Pool = []string{"192.0.2.1:443", "192.0.2.2:443", "[2001:db8::1]:443"}
	a, e := planAddresses(c, k, 3000)
	if e != nil || len(a.Endpoints) != 3 {
		t.Fatal(e)
	}
	c.Pool[0], c.Pool[2] = c.Pool[2], c.Pool[0]
	b, _ := planAddresses(c, k, 3000)
	if !reflect.DeepEqual(a, b) {
		t.Fatal("order depends on input order")
	}
	c.Protected = []string{"::ffff:192.0.2.1"}
	if _, e = planAddresses(c, k, 3000); e == nil {
		t.Fatal("mapped protected address allowed")
	}
	c.Protected = nil
	c.Pool = []string{"192.0.2.1:443", "192.0.2.1:444"}
	if _, e = planAddresses(c, k, 3000); e == nil {
		t.Fatal("port-only pool accepted")
	}
}
