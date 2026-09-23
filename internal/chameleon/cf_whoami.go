package chameleon

// cf_whoami.go — resolver identity probes (OONI "whoami" methodology).
//
// Purpose: distinguish REAL DNS interception from benign anycast variance.
// A whoami query asks an authoritative server "which resolver egress IP did
// you see?" — if the plain UDP:53 path is intercepted by the ISP, the answer
// names the ISP's resolver instead of the expected provider (e.g. Cloudflare).
//
// Measurement only; no evasion logic here.

import (
	"context"
	"errors"
	"net"
	"regexp"
	"strings"
	"time"
)

// ipv4Pattern finds IPv4-looking tokens even when glued to other TXT strings
// (Go's LookupTXT concatenates multi-string TXT records, e.g. "ns172.70.x.x").
var ipv4Pattern = regexp.MustCompile(`\d{1,3}(?:\.\d{1,3}){3}`)

// cloudflareIPv4Ranges — Cloudflare's published IPv4 ranges (cloudflare.com/ips),
// used to verify that a resolver egress belongs to the expected provider when
// the DoH endpoint is Cloudflare (1.1.1.1).
var cloudflareIPv4Ranges = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
}

// whoamiPlain asks whoami.akamai.net (A) via the given plain UDP resolver and
// returns the resolver's egress IP. Fallback: whoami.ds.akahelp.net (TXT).
// A syntactically valid but bogus answer (e.g. private IP) is returned as-is:
// it is itself a hijack signal for evaluateDNSHijack.
func whoamiPlain(ctx context.Context, resolver string, timeout time.Duration) (string, error) {
	r := net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{Timeout: timeout}
		return d.DialContext(ctx, "udp", resolver)
	}}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if ips, err := r.LookupIP(dctx, "ip4", "whoami.akamai.net"); err == nil {
		for _, ip := range ips {
			if ip4 := ip.To4(); ip4 != nil {
				return ip4.String(), nil
			}
		}
	}
	if txts, err := r.LookupTXT(dctx, "whoami.ds.akahelp.net"); err == nil {
		for _, t := range txts {
			if ip := extractFirstIPv4(t); ip != "" {
				return ip, nil
			}
		}
	}
	return "", errors.New("whoami: no resolver identity answer via plain DNS")
}

// whoamiDoH is the same identity probe over the DoH control path.
func whoamiDoH(ctx context.Context, endpoint string, timeout time.Duration) (string, error) {
	if ips, err := resolveViaDoH(ctx, "whoami.akamai.net", endpoint, timeout); err == nil {
		for _, s := range ips {
			if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
				return ip.String(), nil
			}
		}
	}
	d := NewDoHResolver(endpoint)
	d.hc.Timeout = timeout
	if txts, err := d.ResolveTXT("whoami.ds.akahelp.net"); err == nil {
		for _, t := range txts {
			if ip := extractFirstIPv4(t); ip != "" {
				return ip, nil
			}
		}
	}
	return "", errors.New("whoami: no resolver identity answer via DoH")
}

// extractFirstIPv4 returns the first syntactically valid IPv4 address in s.
func extractFirstIPv4(s string) string {
	for _, m := range ipv4Pattern.FindAllString(s, -1) {
		if ip := net.ParseIP(m); ip != nil && ip.To4() != nil {
			return ip.String()
		}
	}
	return ""
}

// isExpectedProviderEgress reports whether egressIP belongs to the provider
// behind the given DoH endpoint. Providers without a known published egress
// set yield "no opinion" (true) so the check never false-fires.
func isExpectedProviderEgress(egressIP, dohEndpoint string) bool {
	e := strings.ToLower(dohEndpoint)
	var ranges []string
	switch {
	case strings.Contains(e, "1.1.1.1") || strings.Contains(e, "1.0.0.1") || strings.Contains(e, "cloudflare"):
		ranges = cloudflareIPv4Ranges
	default:
		return true // unknown provider: no opinion
	}
	ip := net.ParseIP(egressIP)
	if ip == nil {
		return false
	}
	for _, cidr := range ranges {
		if _, n, err := net.ParseCIDR(cidr); err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

// evaluateDNSHijack is the reliable interception verdict. Unlike the raw
// DNSPoisoning discrepancy flag it ignores benign anycast/dual-stack noise
// and fires only when:
//  1. the plain-path resolver egress does NOT belong to the expected provider
//     (for a Cloudflare endpoint: not a Cloudflare IP), or
//  2. a plain answer contains a bogus IP (private/loopback/0.0.0.0/...), or
//  3. the same IP is served for 2+ unrelated domains (captive-portal signature).
func evaluateDNSHijack(prof *CensorProfile, plainByDomain map[string][]string, dohEndpoint string) bool {
	if prof.ResolverPlain != "" && !isExpectedProviderEgress(prof.ResolverPlain, dohEndpoint) {
		return true
	}
	seen := map[string]string{}
	for domain, ips := range plainByDomain {
		for _, s := range ips {
			if ip := net.ParseIP(s); ip != nil && !isPublicResolutionIP(ip) {
				return true // bogus answer (private/loopback/unspecified/...)
			}
			if prev, ok := seen[s]; ok && prev != domain {
				return true // same IP for unrelated domains (captive portal)
			}
			seen[s] = domain
		}
	}
	return false
}

// onlyIPv4 filters resolver answers down to IPv4. DoH probes ask type=A, so
// the plain path must be A-only too — otherwise dual-stack domains always
// mismatch, which is a comparison bug, not censorship.
func onlyIPv4(ips []string) []string {
	out := make([]string, 0, len(ips))
	for _, s := range ips {
		if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
			out = append(out, ip.String())
		}
	}
	return out
}
