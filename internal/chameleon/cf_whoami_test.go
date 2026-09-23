package chameleon

import "testing"

func TestOnlyIPv4FiltersNonA(t *testing.T) {
	in := []string{"1.2.3.4", "::1", "2001:db8::1", "5.6.7.8", "not-an-ip"}
	got := onlyIPv4(in)
	if len(got) != 2 || got[0] != "1.2.3.4" || got[1] != "5.6.7.8" {
		t.Fatalf("onlyIPv4 = %v", got)
	}
}

func TestExtractFirstIPv4(t *testing.T) {
	cases := map[string]string{
		`"ns" "172.70.110.68"`: "172.70.110.68",
		"ns172.70.110.68":      "172.70.110.68", // Go concatenates multi-string TXT
		"no address here":      "",
		"999.1.1.1":            "", // invalid octet must not parse
	}
	for in, want := range cases {
		if got := extractFirstIPv4(in); got != want {
			t.Errorf("extractFirstIPv4(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExpectedProviderEgress(t *testing.T) {
	cf := "https://1.1.1.1/dns-query"
	if !isExpectedProviderEgress("172.70.110.68", cf) {
		t.Fatal("cloudflare egress must match cloudflare endpoint")
	}
	if !isExpectedProviderEgress("162.158.85.1", cf) {
		t.Fatal("162.158.0.0/15 must match cloudflare endpoint")
	}
	if isExpectedProviderEgress("203.0.113.9", cf) {
		t.Fatal("non-cloudflare egress must not match cloudflare endpoint")
	}
	// Unknown provider => no opinion (never false-fires).
	if !isExpectedProviderEgress("203.0.113.9", "https://dns.example.org/query") {
		t.Fatal("unknown provider must yield no-opinion true")
	}
}

func TestEvaluateDNSHijack(t *testing.T) {
	cf := "https://1.1.1.1/dns-query"

	// Clean: egress belongs to Cloudflare, answers public and distinct.
	clean := &CensorProfile{ResolverPlain: "172.70.110.68"}
	if evaluateDNSHijack(clean, map[string][]string{
		"google.com":     {"142.250.1.1", "142.250.1.2"},
		"cloudflare.com": {"104.16.1.1"},
	}, cf) {
		t.Fatal("clean run must not be flagged")
	}

	// Foreign egress: the ISP's resolver answered the plain path.
	if !evaluateDNSHijack(&CensorProfile{ResolverPlain: "203.0.113.9"}, nil, cf) {
		t.Fatal("foreign egress must be flagged")
	}

	// Bogus answer IP (private/loopback/unspecified).
	if !evaluateDNSHijack(&CensorProfile{}, map[string][]string{
		"example.com": {"10.0.0.5"},
	}, cf) {
		t.Fatal("private IP answer must be flagged")
	}

	// Captive-portal signature: same IP served for 2+ unrelated domains.
	if !evaluateDNSHijack(&CensorProfile{}, map[string][]string{
		"a.com": {"95.100.1.1"},
		"b.com": {"95.100.1.1"},
	}, cf) {
		t.Fatal("repeated IP across domains must be flagged")
	}
}

// The selector must ignore raw anycast noise: DoH switch only on the
// reliable hijack verdict; a clean network yields an empty plan (actions: []).
func TestSelectorIgnoresAnycastNoise(t *testing.T) {
	sel := NewAdaptiveCarrierSelector(DefaultCarrierProfiles())
	plan := sel.Select(CensorProfile{DNSPoisoning: true, HasDPI: true, DNSLikelyHijack: false})
	if len(plan.Actions) != 0 {
		t.Fatalf("raw dns_poisoning without hijack must yield empty plan, got %+v", plan.Actions)
	}
	if !plan.LocalPlan {
		t.Fatal("empty plan is fully local")
	}
}
