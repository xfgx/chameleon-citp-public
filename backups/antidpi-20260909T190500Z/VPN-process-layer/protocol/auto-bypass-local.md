# Auto-bypass (local) — adaptive carrier selector

Status: **local planner / decision layer**. Spec version: CITP v2.1.
Implementation: `internal/chameleon/cf_bypass.go`, `tools/cham-autobypass/`.
Windows binary: `dist/cham-autobypass-windows-amd64.exe`.

This document specifies the LOCAL auto-bypass planner. It is an **adaptive
carrier selector**: given a `CensorProfile` (from `cf_profiler.go`), it selects
which CITP carrier strategy to switch to. It is **not** a packet-level evasion
engine.

## Scope boundary (critical)

The selector performs **local carrier selection** only. It does **not**
implement and will not derive:

- Geneva-style packet fragmentation / strategies
  ([Bock et al., CCS 2019](https://geneva.cs.umd.edu/))
- SNI spoofing / domain fronting against a specific censor
- Packet morphing / protocol imitation
- Raw packet crafting

It maps "what the censor does" → "which of the operator's own carriers to use".
Every local/simulated action is marked `mode:"local"` and `local:true`.

## How it works

```
CensorProfile  --[AdaptiveCarrierSelector.Select]-->  BypassPlan
                                                       (actions[], each mode:"local"|"infrastructure")
```

`BypassPlan` contains a list of `BypassAction`s. Each action has:

- `trigger` — what was detected (e.g. `dns_poisoning`, `tls_interference`)
- `strategy` — the recommended carrier/transport
- `mode` — `"local"` (client can do it now) or `"infrastructure"` (needs real infra)
- `description` — human-readable
- `local` — `true` for every local action

## Decision table

| Detected | Strategy | Mode | Local? |
|----------|----------|------|--------|
| DNS poisoning | switch resolver path to DoH carrier (`citp-carrier-doh`) | local | yes |
| HTTP block page | rotate local endpoint/decoy origin | local | yes |
| TCP reset injection | rotate to alternate CITP carrier profile (local config) | local | yes |
| TLS/SNI interference | alternate carrier (local) + refraction carrier (infra) | local + infrastructure | mixed |
| SNI interference (severe) | refraction carrier (`refraction-tls`) | infrastructure | **no** — needs on-path station |
| No interference | keep current carrier | local | yes |

`BypassPlan.LocalPlan` is `true` only when every action is `mode:"local"`
(i.e. the plan is fully executable locally without extra infrastructure).

## What is local vs infrastructure-gated

**Local (mode:"local")** — the client switches among its own configured carriers:
DoH resolver carrier, alternate entry/carrier profiles, decoy origin rotation.
These are LOCAL DATA (local config, local decision). The switch itself is a
local control-plane action; the carriers are the operator's existing CITP
transports.

**Infrastructure-gated (mode:"infrastructure")** — remain
`ErrRequiresInfrastructure`:
- refraction / on-path station (needs cooperative ISP — see
  `protocol/refraction.md`, [TapDance, USENIX 2014](https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/wustrow))
- BGP announce/withdraw (needs own ASN/prefix — see `protocol/censor-profiling.md` §3.1)
- foreign-CDN priming (needs owned object storage + credentials — §3.2)

When SNI interference is severe, the only fully-SNI-hidden carrier is the
refraction carrier, which is infrastructure-gated. The selector surfaces this
honestly: the plan is **not** `LocalPlan` and the action is `mode:"infrastructure"`.

## Usage

```bash
# Linux (lab):
go run ./tools/cham-autobypass

# Windows 11 (standalone):
cham-autobypass-windows-amd64.exe
# optionally add curated SNI probes:
set CITP_SNI_LIST=example.com,other.org
cham-autobypass-windows-amd64.exe
```

In-tree: `plan := NewAdaptiveCarrierSelector(profiles).Select(profile)`.

## What it is NOT (wording)

This is a "local auto-bypass planner / adaptive carrier selector." It
"automatically selects a local carrier strategy based on the measured censor
profile." It does **not** "defeat the provider's DPI" by itself — for the
hard cases (SNI hiding, on-path redirection) it routes to infrastructure-gated
actions that require a real cooperative deployment.

## Windows notes

- The profiler's TTL localizer (`tracerouteRSTScan`) needs raw sockets. On
  Windows this requires Administrator privileges; without them it returns
  `censor_hop_ttl: -1` with a note (graceful degradation). The rest of the
  probe suite (DoH, TCP reset, TLS, HTTP block-page) works without privileges.
- The `.exe` is built with `GOOS=windows GOARCH=amd64` and is self-contained.
