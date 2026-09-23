package chameleon

// cf_bgp.go — BGP control-plane channel.
//
// READ-ONLY reader: queries the public RIPEstat routing-info API for the
// current AS-path of a prefix. This demonstrates how a "control-plane beacon"
// could be read by a client using only an ordinary HTTPS request to a public
// measurement service — visible to the data-plane DPI as normal web traffic.
//
// WRITING BGP (announce/withdraw, AS-path prepending, communities) is NOT
// implemented and intentionally returns ErrRequiresInfrastructure. Real BGP
// writes require lawful control of an Autonomous System and a globally
// routable prefix; uncontrolled route flapping can destabilise global routing
// and is explicitly out of scope.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// ErrRequiresInfrastructure is returned by any control operation that needs
// real-world infrastructure (AS/prefix, on-path station, owned CDN).
var ErrRequiresInfrastructure = errors.New("control-fabric: operation requires authorized infrastructure (AS/prefix, on-path station, or owned CDN)")

// BGPRoute is a single observed route for a prefix.
type BGPRoute struct {
	Origin string   `json:"origin"`
	ASPath []string `json:"aspath"`
}

// BGPControlChannel is the read-only BGP beacon reader.
type BGPControlChannel struct {
	ripestatURL string
	hc          *http.Client
}

// NewBGPControlChannel constructs a reader pointing at RIPEstat.
func NewBGPControlChannel(ripestatURL string) *BGPControlChannel {
	if ripestatURL == "" {
		ripestatURL = "https://stat.ripe.net/data/prefix-overview/data.json"
	}
	return &BGPControlChannel{ripestatURL: ripestatURL, hc: &http.Client{Timeout: 15 * time.Second}}
}

// ReadASPath reads the real origin/AS path for a prefix via the RIPEstat
// prefix-overview data call (read-only, no local routing dependency).
func (b *BGPControlChannel) ReadASPath(ctx context.Context, prefix string) ([]BGPRoute, error) {
	url := b.ripestatURL + "?resource=" + prefix
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := b.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errHTTPStatus(resp.StatusCode)
	}
	var payload struct {
		Data struct {
			Announced bool `json:"announced"`
			ASNs      []struct {
				ASN    int    `json:"asn"`
				Holder string `json:"holder"`
			} `json:"asns"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	if !payload.Data.Announced {
		return nil, errors.New("control-fabric: prefix not globally announced")
	}
	routes := make([]BGPRoute, 0, len(payload.Data.ASNs))
	for _, a := range payload.Data.ASNs {
		origin := fmt.Sprintf("AS%d", a.ASN)
		routes = append(routes, BGPRoute{Origin: origin, ASPath: []string{origin, a.Holder}})
	}
	return routes, nil
}

// Announce is a stub: real BGP writes require lawful AS/prefix control.
func (b *BGPControlChannel) Announce(prefix string, asPath []string) error {
	_ = prefix
	_ = asPath
	return ErrRequiresInfrastructure
}

// Withdraw is a stub: real BGP writes require lawful AS/prefix control.
func (b *BGPControlChannel) Withdraw(prefix string) error {
	_ = prefix
	return ErrRequiresInfrastructure
}

// RoutingHistory fetches real routing history from RIPEstat (read-only) and
// returns the per-origin route counts. This is real internet data.
func (b *BGPControlChannel) RoutingHistory(ctx context.Context, prefix string) ([]BGPRoute, error) {
	url := "https://stat.ripe.net/data/routing-history/data.json?resource=" + prefix + "&normalize=1"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := b.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errHTTPStatus(resp.StatusCode)
	}
	var payload struct {
		Data struct {
			ByOrigin []struct {
				Origin string `json:"origin"`
				Routes []struct {
					Timelines []struct {
						Updates []json.RawMessage `json:"updates"`
					} `json:"timelines"`
				} `json:"routes"`
			} `json:"by_origin"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	out := make([]BGPRoute, 0, len(payload.Data.ByOrigin))
	for _, o := range payload.Data.ByOrigin {
		routeCount := len(o.Routes)
		upd := 0
		for _, r := range o.Routes {
			for _, tl := range r.Timelines {
				upd += len(tl.Updates)
			}
		}
		out = append(out, BGPRoute{Origin: o.Origin, ASPath: []string{"routes=" + itoa(routeCount), "updates=" + itoa(upd)}})
	}
	return out, nil
}

// BeaconSnapshot returns a real, stable hash of the current AS-path state for
// a prefix, so a client can detect changes (control-plane beacon) by polling.
func (b *BGPControlChannel) BeaconSnapshot(ctx context.Context, prefix string) (string, error) {
	routes, err := b.ReadASPath(ctx, prefix)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	for _, r := range routes {
		_, _ = h.Write([]byte(r.Origin))
		for _, a := range r.ASPath {
			_, _ = h.Write([]byte(a))
			_, _ = h.Write([]byte{','})
		}
		_, _ = h.Write([]byte{'|'})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
