# Censor profiling — DPI detection & infrastructure requirements

Status: **measurement/diagnostics layer**. Spec version: CITP v2.1.
Implementation: `internal/chameleon/cf_profiler.go`, `tools/cham-profiler/`.

This document answers three questions:

1. What infrastructure is needed to make the remaining Control Fabric stubs
   real (BGP write, foreign-CDN priming, on-path refraction station)?
2. How do you detect the ISP's DPI, and does it auto-detect?
3. How is the profiler wired into CITP?

## 0. Scope boundary (important)

The profiler is **measurement only** — it detects and characterizes censorship.
It is **not** an evasion engine: it contains no Geneva-style fragmentation
strategies, no SNI spoofing, no packet morphing, no automatic bypass selection.
Choosing and running a bypass remains a documented infrastructure requirement
(§3). Methodology follows OONI's control-vs-experiment comparison
([OONI Web Connectivity](https://ooni.org/nettest/web-connectivity/),
[OONI spec ts-017](https://github.com/ooni/spec/blob/master/nettests/ts-017-web-connectivity.md)).

## 1. How DPI is detected (auto-profile)

`DPIProfiler.Run(ctx)` runs a probe suite and produces a `CensorProfile`:

| Probe | What it detects | How |
|-------|-----------------|-----|
| `probeDNSPoisoning` | DNS tampering | Compares the **same resolver** over plain UDP:53 vs DoH (e.g. `1.1.1.1:53` vs `https://1.1.1.1/dns-query`). Same resolver, different transport: a disagreement implies on-path tampering of plain DNS. |
| `probeTCPReset` | TCP RST injection | Dials a probe host and writes a benign request; a reset right after establishment hints at RST injection. |
| `probeTLSHandshake` | SNI/TLS interference | Performs a real TLS handshake with an operator-curated SNI; a reset after ClientHello indicates SNI-based blocking ([OONI FAQ](https://ooni.org/support/faq/), [NDSS DoT/DoH paper](https://www.ndss-symposium.org/wp-content/uploads/dnspriv21-02-paper.pdf)). |
| `probeHTTPBlockPage` | HTTP block page | HTTP GET; flags status 403/451 or a body matching a configured signature, or a body fingerprint that differs from control. |
| `localizeCensorHop` | On-path censor location | TTL-based traceroute scan (TCP SYN with increasing TTL, classify ICMP TIME EXCEEDED vs injected RST). Needs `CAP_NET_RAW`; degrades gracefully otherwise. |

**Does the DPI "auto-detect"?** Yes and no:

- **Yes** for the profile: `Run()` automatically executes all probes and returns
  a `CensorProfile` (`has_dpi`, per-mechanism booleans, poisoned domains, block
  signatures, censor hop TTL). The client can run this on bootstrap.
- **No** for "the DPI magically appears as a usable transport." A DPI is only
  observable from the client's network by measuring it; it does not auto-mount
  as a channel. The Control Fabric's CAR channel uses the profile's detected
  block-signatures to interpret verdicts, but the actual on-path station must
  already exist (§3.3).

The probe domains / SNI list are **operator-curated** (like OONI's
[Citizen Lab test lists](https://ooni.org/post/web-connectivity/)). The
profiler never hardcodes or downloads "banned" lists and never invents SNIs.

### 1.1 Known measurement subtleties (documented, not hidden)

- **DNS false positives:** comparing two *different* resolvers' anycast IPs
  can disagree without censorship. The probe mitigates this by querying the
  *same* resolver over UDP vs DoH. In sandboxes/cloud egress where outbound
  UDP:53 is redirected, the probe will (correctly) flag a disagreement — that
  is the sandbox intercepting plain DNS, not a bug.
- **Block-page signatures:** must be curated per censor; the profiler does not
  guess. Operators supply signatures via `ProfilerConfig.BlockSignatures`.
- **TTL localization:** requires raw sockets; without `CAP_NET_RAW` it returns
  `censor_hop_ttl: -1` with a note. On Windows, use a privileged driver or run
  the profiler on a Linux probe host.

## 2. How the profile feeds CITP

`ControlFabric.Profile(ctx, cfg)` runs the profiler. The resulting
`CensorProfile.BlockSignatures` are fed to the CAR reader via
`CARReader.WithBlockSignatures(...)`, so verdict detection uses the censor's
actual block-page markers instead of a static token. The profile is JSON-
serializable (`ProfilerJSON`) and can be published through the Control Fabric
bulletin as a tiny control message so other clients share the same censor map.

## 3. Infrastructure needed to make the stubs real

These remain `ErrRequiresInfrastructure` because they need physical/
authoritative resources that a local node cannot conjure. Each is documented
honestly below.

### 3.1 BGP Announce / Withdraw

To originate or change a route announcement you need:

- An **Autonomous System Number (ASN)** and a globally routable IP prefix,
  allocated by an RIR (RIPE NCC, ARIN, APNIC…) with an RPKI certificate.
- **BGP sessions** with at least two upstreams/transit providers or an IXP
  route-server, configured via a daemon like
  [FRRouting](https://frrouting.org/) or [GoBGP](https://github.com/osrg/gobgp).
- RPKI ROA and IRR objects so your announcement is accepted as valid.

The Control Fabric's `BGPControlChannel.Announce`/`Withdraw` return
`ErrRequiresInfrastructure` because issuing real announcements from an
arbitrary VPS would be route hijacking. The **read-only** path (RIPEstat
`prefix-overview` + `routing-history`) is real and live.

### 3.2 Foreign-CDN / object-store priming

To use a CDN or object store as the control-plane bulletin you need:

- An **owned CDN or object-storage bucket** (Cloudflare R2, AWS S3, Backblaze
  B2, …) with API credentials (access key + secret).
- A **domain** (optionally delegated) to serve the bulletin over HTTPS that
  looks legitimate.
- Rotating keys and short TTLs to limit caching.

The bulletin's local in-memory backend is marked `LOCAL DATA`. A real
deployment would back `CDNCacheStateChannel` with an S3-compatible client;
credentials must come from the operator (never hardcoded). The interface is
already in place (`CDNCacheStateClient.Upload`/`Poll`); only the storage
backend is local.

### 3.3 On-path refraction station (the hard one)

Refraction networking places proxy functionality **in the middle of the
network**, at a participating ISP or network operator — not at an endpoint.
This is the TapDance family of systems
([Wustrow et al., USENIX Security 2014](https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/wustrow),
[ISP-scale deployment, FOCI 2017](https://www.usenix.org/conference/foci17/workshop-program/presentation/frolov),
[Refraction Networking](https://refraction.network/)). It requires:

- A **cooperative ISP, transit provider, or IXP** that can place a station
  on the traffic path — via an optical splitter or a router port mirroring the
  link. The station passively inspects a copy of traffic and injects packets.
- **Routing reachability:** the client's route to chosen decoy origins must
  pass by the station.
- A **steganographic tag** the client embeds in TLS ciphertext that the station
  can read but a censor cannot (TapDance uses chosen-ciphertext steganography).

**A local node cannot become on-path for a foreign ISP by itself.** This is
why `RefractionCarrier` (see `protocol/refraction.md`) is a documented stub:
making it operational requires the cooperative on-path deployment above. The
profiler (§1) is what tells you whether such a station would even be needed in
a given network.

### 3.4 What is deliberately NOT automated

Per the safe-by-design boundary, the following are **not** implemented and
will not be auto-derived from a profile:

- Evasion strategy search (Geneva-style genetic fragmentation,
  [Bock et al., CCS 2019](https://geneva.cs.umd.edu/)).
- SNI spoofing / domain fronting against a specific censor.
- Packet morphing / protocol imitation engines.
- Automatic selection and launch of a bypass based on the profile.

The profile describes what the censor does; **deciding how (or whether) to
evade is an operator decision** requiring the infrastructure in §3.

## 4. CLI

```bash
go run ./tools/cham-profiler            # prints a JSON CensorProfile
CITP_SNI_LIST=example.com,other.org \
  go run ./tools/cham-profiler          # add curated SNI probes
```

The profiler is also reachable in-tree via
`ControlFabric.Profile(ctx, ProfilerConfig{...})`.
