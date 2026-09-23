package chameleon

// cf_doh.go — REAL DNS-over-HTTPS client.
//
// Performs real DoH JSON queries against a public resolver (default: Cloudflare
// 1.1.1.1). To the on-path DPI this looks like ordinary HTTPS to a large
// public domain. The node's authoritative TXT server stays LOCAL (see
// cf_dns.go); this DoH client is the "looks-like-normal-HTTPS" reader path.
// For a real dead-drop over DoH, the node's zone must be publicly delegated;
// here the reader is fully functional against any real delegated name.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DoHResolver performs real DNS-over-HTTPS queries against a public resolver.
type DoHResolver struct {
	endpoint string
	hc       *http.Client
}

// NewDoHResolver constructs a real DoH resolver. endpoint defaults to Cloudflare.
func NewDoHResolver(endpoint string) *DoHResolver {
	if endpoint == "" {
		endpoint = "https://1.1.1.1/dns-query"
	}
	return &DoHResolver{endpoint: endpoint, hc: &http.Client{Timeout: 8 * time.Second}}
}

// ResolveTXT resolves the TXT record for name via real DoH. Returns the joined
// data strings(s) (with surrounding quotes stripped).
func (d *DoHResolver) ResolveTXT(name string) ([]string, error) {
	u := d.endpoint + "?name=" + url.QueryEscape(name) + "&type=TXT"
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := d.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh: http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var payload struct {
		Status int `json:"Status"`
		Answer []struct {
			Name string `json:"name"`
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	if payload.Status != 0 {
		return nil, fmt.Errorf("doh: rcode %d", payload.Status)
	}
	var out []string
	for _, a := range payload.Answer {
		if a.Type == 16 { // TXT
			out = append(out, strings.Trim(a.Data, `"`))
		}
	}
	return out, nil
}

// ResolveA резолвит A-записи (IPv4) имени через DoH (dns-json API).
// Используется автопилотом клиента для обхода перехвата plain-DNS
// провайдером: адрес ноды резолвится по защищённому каналу.
func (d *DoHResolver) ResolveA(ctx context.Context, name string) ([]string, error) {
	u := d.endpoint + "?name=" + url.QueryEscape(name) + "&type=A"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := d.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh: http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var payload struct {
		Status int `json:"Status"`
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	if payload.Status != 0 {
		return nil, fmt.Errorf("doh: rcode %d", payload.Status)
	}
	var out []string
	for _, a := range payload.Answer {
		if a.Type == 1 { // A
			if ip := net.ParseIP(a.Data); ip != nil && ip.To4() != nil {
				out = append(out, ip.String())
			}
		}
	}
	return out, nil
}
