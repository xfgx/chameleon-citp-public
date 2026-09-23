package main

// Experimental offline rendezvous planner. It never configures or probes IPs.
// Hopping is not authentication: all connections must still use pinned mTLS.
import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
)

type Schedule struct {
	Prefix               string   `json:"prefix,omitempty"`
	Pool                 []string `json:"allocated_endpoints,omitempty"`
	FullPrefixAuthorized bool     `json:"full_prefix_authorized"`
	KeyFile              string   `json:"hop_key_file"`
	NodeID               string   `json:"node_id"`
	StepSeconds          int64    `json:"step_seconds"`
	Port                 uint16   `json:"port"`
	Protected            []string `json:"protected_ips"`
}

type AddressPlan struct {
	Epoch         int64    `json:"epoch"`
	Endpoints     []string `json:"endpoints"`
	NetworkAction string   `json:"network_action"`
}

func planAddresses(c Schedule, secret []byte, unix int64) (AddressPlan, error) {
	fail := func(s string) (AddressPlan, error) { return AddressPlan{}, errors.New(s) }
	if len(secret) != 32 {
		return fail("hop key must be exactly 32 random bytes")
	}
	node, e := hex.DecodeString(c.NodeID)
	if e != nil || len(node) != 32 {
		return fail("node_id must be a 32-byte public-key digest")
	}
	if c.StepSeconds < 5 || c.StepSeconds > 3600 || unix < 0 || unix > 1<<61 {
		return fail("invalid step or time")
	}
	if (c.Prefix == "") == (len(c.Pool) == 0) {
		return fail("provide exactly one allocated pool or prefix")
	}
	deny := map[netip.Addr]bool{}
	for _, s := range c.Protected {
		ip, e := netip.ParseAddr(s)
		if e != nil || ip.Zone() != "" {
			return fail("invalid protected IP")
		}
		deny[ip.Unmap()] = true
	}
	epoch := unix / c.StepSeconds
	prf := func(ep int64, resource string) []byte {
		m := hmac.New(sha256.New, secret)
		m.Write([]byte("KS-RV1\x00"))
		m.Write(node)
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(c.StepSeconds))
		m.Write(b[:])
		binary.BigEndian.PutUint64(b[:], uint64(ep))
		m.Write(b[:])
		m.Write([]byte(resource))
		return m.Sum(nil)
	}
	p := AddressPlan{Epoch: epoch, NetworkAction: "none: computation only"}
	if c.Prefix != "" {
		n, e := netip.ParsePrefix(c.Prefix)
		if e != nil || !n.Addr().Is6() || n.Addr().Is4In6() || n.Bits() != 64 || n != n.Masked() || !n.Addr().IsGlobalUnicast() || !c.FullPrefixAuthorized || c.Port == 0 {
			return fail("requires an explicitly authorized, aligned IPv6 /64 and a port; interface /64 alone is NOT authorization")
		}
		for _, ep := range []int64{epoch, epoch - 1, epoch + 1} {
			if ep < 0 {
				continue
			}
			b := n.Addr().As16()
			sum := prf(ep, "prefix:"+n.String()+":"+fmt.Sprint(c.Port))
			iid := binary.BigEndian.Uint64(sum[:8]) & 0x7fffffffffffffff
			if iid < 65536 {
				return fail("reserved low interface identifier: fail closed")
			}
			binary.BigEndian.PutUint64(b[8:], iid)
			ip := netip.AddrFrom16(b)
			if deny[ip] {
				return fail("derived address is protected: fail closed")
			}
			p.Endpoints = append(p.Endpoints, netip.AddrPortFrom(ip, c.Port).String())
		}
	} else {
		if len(c.Pool) < 2 || len(c.Pool) > 256 {
			return fail("explicit pool must contain 2..256 endpoints")
		}
		type ranked struct {
			ep    string
			score []byte
		}
		r := []ranked{}
		seen := map[netip.AddrPort]bool{}
		ips := map[netip.Addr]bool{}
		for _, s := range c.Pool {
			a, e := parseEndpoint(s)
			if e != nil {
				return fail("invalid pool endpoint")
			}
			if deny[a.Addr()] || seen[a] {
				return fail("protected or duplicate endpoint")
			}
			seen[a] = true
			ips[a.Addr()] = true
			r = append(r, ranked{a.String(), prf(epoch, "pool:"+a.String())})
		}
		if len(ips) < 2 {
			return fail("port changes alone are not IP rotation")
		}
		sort.Slice(r, func(i, j int) bool {
			if q := bytes.Compare(r[i].score, r[j].score); q != 0 {
				return q < 0
			}
			return r[i].ep < r[j].ep
		})
		for _, v := range r {
			p.Endpoints = append(p.Endpoints, v.ep)
		}
	}
	return p, nil
}

func planFile(path string, unix int64) (AddressPlan, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return AddressPlan{}, e
	}
	if len(b) > 16384 {
		return AddressPlan{}, errors.New("schedule too large")
	}
	var c Schedule
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e = d.Decode(&c); e != nil {
		return AddressPlan{}, e
	}
	var extra interface{}
	if d.Decode(&extra) != io.EOF {
		return AddressPlan{}, errors.New("trailing schedule content")
	}
	keyPath := c.KeyFile
	if !filepath.IsAbs(keyPath) {
		keyPath = filepath.Join(filepath.Dir(path), keyPath)
	}
	secret, e := os.ReadFile(keyPath)
	if e != nil {
		return AddressPlan{}, errors.New("cannot read hopping key file")
	}
	return planAddresses(c, secret, unix)
}
