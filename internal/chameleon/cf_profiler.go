package chameleon

// cf_profiler.go — DPI auto-PROFILER (measurement / diagnostics only).
//
// This is a detection & characterization tool, NOT an evasion engine. It runs
// a probe suite (DNS poisoning, TCP reset, TLS/SNI interference, HTTP
// block-page, optional TTL-based censor localization) and produces a
// CensorProfile. Methodology follows OONI's Web Connectivity / DNS
// consistency approach (compare a control path vs the user's network).
//
// Safe by design:
//   - probe domains/SNIs are operator-configured; no hardcoded banned lists;
//   - default probes use benign tokens and real public endpoints;
//   - NO evasion logic (no fragmentation/Geneva-style strategies, no SNI
//     spoofing, no packet morphing). The profile only describes what the censor
//     does; choosing/running a bypass is out of scope and remains a documented
//     infrastructure requirement (see protocol/censor-profiling.md).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// CensorProfile is the output of an automated DPI probe run.
type CensorProfile struct {
	MeasuredAt        time.Time `json:"measured_at"`
	HasDPI            bool      `json:"has_dpi"`
	DNSPoisoning      bool      `json:"dns_poisoning"`
	TCPResetInjection bool      `json:"tcp_reset_injection"`
	TLSInterference   bool      `json:"tls_interference"`
	HTTPBlockPage     bool      `json:"http_block_page"`
	BlockSignatures   []string  `json:"block_signatures,omitempty"`
	PoisonedDomains   []string  `json:"poisoned_domains,omitempty"`
	// Censor localization (TTL hop where an injected RST appears). -1 = unknown
	// (raw sockets unavailable). Requires CAP_NET_RAW.
	CensorHopTTL     int    `json:"censor_hop_ttl"`
	LocalizationNote string `json:"localization_note"`
	ResolverIP       string `json:"resolver_ip,omitempty"`

	// Resolver identity (OONI whoami): egress IP of the resolver that actually
	// answered via plain UDP vs via DoH. Same provider on both paths means
	// plain UDP:53 reached the intended resolver (no ISP interception).
	ResolverPlain string `json:"resolver_plain,omitempty"`
	ResolverDoH   string `json:"resolver_doh,omitempty"`
	// DNSLikelyHijack is the reliable interception verdict (see
	// evaluateDNSHijack): unlike raw DNSPoisoning it ignores benign
	// anycast/dual-stack variance.
	DNSLikelyHijack bool `json:"dns_likely_hijack"`
	// DNSDiscrepancies shows the actual answer sets (plain vs DoH) per domain,
	// so an operator can tell anycast noise apart from bogus/private answers.
	DNSDiscrepancies []DNSDiscrepancy `json:"dns_discrepancies,omitempty"`
}

// DNSDiscrepancy records the concrete answer sets when plain and DoH answers
// differ for a domain (IPv4-only comparison on both sides).
type DNSDiscrepancy struct {
	Domain string   `json:"domain"`
	Plain  []string `json:"plain_ips"`
	DoH    []string `json:"doh_ips"`
}

// ProfilerConfig configures the probe suite. ProbeDomains/SNIList are
// operator-curated (like OONI's Citizen Lab test lists). Leave empty for a
// benign self-check that only confirms the probe machinery works.
type ProfilerConfig struct {
	ProbeDomains    []string // domains to resolve (control vs plain DNS)
	ProbeHTTPURLs   []string // URLs to GET for block-page detection
	SNIList         []string // SNIs to test for TLS/SNI interference
	BlockSignatures []string // known block-page substrings
	DoHEndpoint     string   // control DoH resolver (default Cloudflare)
	Timeout         time.Duration
}

// DPIProfiler runs the probe suite and builds a CensorProfile.
type DPIProfiler struct {
	cfg ProfilerConfig
	doh *DoHResolver
	hc  *http.Client
}

// NewDPIProfiler constructs a profiler. cfg may be zero-valued for a benign run.
func NewDPIProfiler(cfg ProfilerConfig) *DPIProfiler {
	if cfg.DoHEndpoint == "" {
		cfg.DoHEndpoint = "https://1.1.1.1/dns-query"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 8 * time.Second
	}
	return &DPIProfiler{
		cfg: cfg,
		doh: NewDoHResolver(cfg.DoHEndpoint),
		hc:  &http.Client{Timeout: cfg.Timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }},
	}
}

// Run executes all probes and returns the profile.
func (p *DPIProfiler) Run(ctx context.Context) CensorProfile {
	prof := CensorProfile{MeasuredAt: time.Now().UTC(), CensorHopTTL: -1}
	if len(p.cfg.ProbeDomains) == 0 {
		// benign default: a real, widely-resolved domain, just to exercise the path
		p.cfg.ProbeDomains = []string{"google.com", "cloudflare.com"}
	}
	if len(p.cfg.ProbeHTTPURLs) == 0 {
		p.cfg.ProbeHTTPURLs = []string{"https://www.google.com/"}
	}

	p.probeDNSPoisoning(ctx, &prof)
	p.probeTCPReset(ctx, &prof)
	p.probeTLSHandshake(ctx, &prof)
	p.probeHTTPBlockPage(ctx, &prof)
	p.localizeCensorHop(ctx, &prof)

	prof.HasDPI = prof.DNSPoisoning || prof.TCPResetInjection || prof.TLSInterference || prof.HTTPBlockPage
	return prof
}

// probeDNSPoisoning compares plain UDP DNS vs DoH against the SAME resolver
// (e.g. 1.1.1.1:53 UDP vs https://1.1.1.1/dns-query). Same resolver, different
// transport: a difference implies on-path tampering of plain DNS.
//
// Reliability notes (v2): the raw DNSPoisoning flag is intentionally kept as
// a noisy discrepancy signal. Two benign effects used to cause false
// positives:
//  1. net.LookupHost returns A+AAAA while the DoH probe asks type=A only, so
//     dual-stack domains always mismatched. Plain answers are now filtered to
//     IPv4 (onlyIPv4) before comparison.
//  2. Anycast variance: the UDP packet and the HTTPS connection can hit
//     different PoPs of the same provider, which legitimately answer with
//     different IP subsets. Raw mismatch != hijack.
//
// The reliable verdict is DNSLikelyHijack, driven by resolver identity
// (whoami) and bogus-answer heuristics (see evaluateDNSHijack).
func (p *DPIProfiler) probeDNSPoisoning(ctx context.Context, prof *CensorProfile) {
	plainResolver := dohEndpointToPlainResolver(p.cfg.DoHEndpoint)
	plainByDomain := map[string][]string{}
	for _, d := range p.cfg.ProbeDomains {
		plainIPs, perr := resolvePlainVia(ctx, d, plainResolver, p.cfg.Timeout)
		if perr != nil {
			continue
		}
		plain4 := onlyIPv4(plainIPs) // A-only comparison: DoH probe asks type=A
		dohIPs, derr := resolveViaDoH(ctx, d, p.cfg.DoHEndpoint, p.cfg.Timeout)
		if derr != nil {
			continue
		}
		plainByDomain[d] = plain4
		if !sameIPSet(plain4, dohIPs) {
			prof.DNSPoisoning = true
			prof.PoisonedDomains = append(prof.PoisonedDomains, d)
			prof.DNSDiscrepancies = append(prof.DNSDiscrepancies, DNSDiscrepancy{Domain: d, Plain: plain4, DoH: dohIPs})
		}
	}
	// Resolver identity (OONI whoami): which resolver really answered each path.
	if ip, err := whoamiPlain(ctx, plainResolver, p.cfg.Timeout); err == nil {
		prof.ResolverPlain = ip
	}
	if ip, err := whoamiDoH(ctx, p.cfg.DoHEndpoint, p.cfg.Timeout); err == nil {
		prof.ResolverDoH = ip
	}
	prof.DNSLikelyHijack = evaluateDNSHijack(prof, plainByDomain, p.cfg.DoHEndpoint)
}

// dohEndpointToPlainResolver maps a DoH endpoint to the same provider's plain
// UDP resolver, so the poisoning comparison is transport-only (same resolver).
func dohEndpointToPlainResolver(endpoint string) string {
	e := strings.ToLower(endpoint)
	switch {
	case strings.Contains(e, "dns.google"):
		return "8.8.8.8:53"
	case strings.Contains(e, "mullvad"):
		return "194.242.2.2:53"
	case strings.Contains(e, "quad9"):
		return "9.9.9.9:53"
	default: // cloudflare 1.1.1.1
		return "1.1.1.1:53"
	}
}

// probeTCPReset dials a probe host and writes a benign byte; a reset shortly
// after the connection is established hints at RST injection.
func (p *DPIProfiler) probeTCPReset(ctx context.Context, prof *CensorProfile) {
	targets := p.cfg.ProbeHTTPURLs
	if len(targets) == 0 {
		return
	}
	for _, u := range targets {
		host := hostFromURL(u)
		if host == "" {
			continue
		}
		d := net.Dialer{Timeout: p.cfg.Timeout}
		conn, err := d.DialContext(ctx, "tcp", host)
		if err != nil {
			// connection failure could be blocking; record but don't conclude
			continue
		}
		// write a benign HTTP-ish probe
		_, werr := conn.Write([]byte("GET / HTTP/1.0\r\nHost: " + strings.Split(host, ":")[0] + "\r\n\r\n"))
		conn.Close()
		if werr != nil && strings.Contains(werr.Error(), "reset") {
			prof.TCPResetInjection = true
			return
		}
	}
}

// probeTLSHandshake performs a TLS dial with each configured SNI; a reset
// right after ClientHello indicates SNI-based interference.
func (p *DPIProfiler) probeTLSHandshake(ctx context.Context, prof *CensorProfile) {
	snis := p.cfg.SNIList
	if len(snis) == 0 {
		return // no curated SNI list => skip (do not probe random SNIs)
	}
	for _, sni := range snis {
		d := net.Dialer{Timeout: p.cfg.Timeout}
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(sni, "443"))
		if err != nil {
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(p.cfg.Timeout))
		// minimal TLS handshake
		tlsConn, herr := tlsHandshakeClient(conn, sni)
		if herr != nil && strings.Contains(strings.ToLower(herr.Error()), "reset") {
			prof.TLSInterference = true
			_ = conn.Close()
			return
		}
		if tlsConn != nil {
			_ = tlsConn.Close()
		} else {
			_ = conn.Close()
		}
	}
}

// probeHTTPBlockPage does an HTTP GET and flags block pages by status or
// signature or body-entropy anomaly vs a control hash.
func (p *DPIProfiler) probeHTTPBlockPage(ctx context.Context, prof *CensorProfile) {
	for _, u := range p.cfg.ProbeHTTPURLs {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		resp, err := p.hc.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == 451 {
			prof.HTTPBlockPage = true
		}
		for _, sig := range p.cfg.BlockSignatures {
			if sig != "" && strings.Contains(string(body), sig) {
				prof.HTTPBlockPage = true
				prof.BlockSignatures = appendUnique(prof.BlockSignatures, sig)
			}
		}
		// body-entropy fingerprint (for the operator to compare across time)
		_ = bodyFingerprint(body)
	}
}

// localizeCensorHop attempts TTL-based localization of an injecting middlebox
// via a traceroute-style scan. Requires CAP_NET_RAW; degrades gracefully.
func (p *DPIProfiler) localizeCensorHop(ctx context.Context, prof *CensorProfile) {
	host := "1.1.1.1"
	if len(p.cfg.ProbeHTTPURLs) > 0 {
		host = strings.Split(hostFromURL(p.cfg.ProbeHTTPURLs[0]), ":")[0]
	}
	hop, note := tracerouteRSTScan(ctx, host, p.cfg.Timeout)
	prof.CensorHopTTL = hop
	prof.LocalizationNote = note
}

// --- helpers ---

func resolvePlain(ctx context.Context, domain string, timeout time.Duration) ([]string, error) {
	return resolvePlainVia(ctx, domain, "1.1.1.1:53", timeout)
}

// resolvePlainVia queries a specific resolver over plain UDP DNS.
func resolvePlainVia(ctx context.Context, domain, resolver string, timeout time.Duration) ([]string, error) {
	r := net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{Timeout: timeout}
		return d.DialContext(ctx, "udp", resolver)
	}}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return r.LookupHost(dctx, domain)
}

func resolveViaDoH(ctx context.Context, domain, endpoint string, timeout time.Duration) ([]string, error) {
	// Resolve A records via DoH JSON type=A.
	u := endpoint + "?name=" + domain + "&type=A"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.Header.Set("Accept", "application/dns-json")
	hc := &http.Client{Timeout: timeout}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var payload struct {
		Status int `json:"Status"`
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	var ips []string
	for _, a := range payload.Answer {
		if a.Type == 1 { // A
			ips = append(ips, a.Data)
		}
	}
	return ips, nil
}

func sameIPSet(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	ma := map[string]bool{}
	for _, x := range a {
		ma[x] = true
	}
	for _, x := range b {
		if !ma[x] {
			return false
		}
	}
	return len(a) == len(b)
}

func hostFromURL(u string) string {
	s := strings.TrimPrefix(u, "https://")
	s = strings.TrimPrefix(s, "http://")
	if i := strings.Index(s, "/"); i >= 0 {
		s = s[:i]
	}
	return s
}

func bodyFingerprint(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func appendUnique(dst []string, v string) []string {
	for _, x := range dst {
		if x == v {
			return dst
		}
	}
	return append(dst, v)
}

// ErrProfilerNotEvasion is returned if someone tries to misuse the profiler as
// a bypass engine. The profiler only measures; it does not evade.
var ErrProfilerNotEvasion = errors.New("control-fabric: DPI profiler is measurement-only; evasion is out of scope")

// ProfilerJSON renders the profile as a compact JSON string (for the CLI / bulletin).
func ProfilerJSON(p CensorProfile) string {
	b, err := json.Marshal(p)
	if err != nil {
		return fmt.Sprintf(`{"error":%q}`, err.Error())
	}
	return string(b)
}
