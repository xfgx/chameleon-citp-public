# Refraction networking — on-path carrier (stub)

Status: **experimental stub**. Spec version: CITP v2.1.

The `refraction-tls` carrier is an architectural layer for a TapDance-class
scenario: the client establishes an ordinary TLS session to a decoy domain,
and a cooperative on-path station in a foreign network validates a hidden
cryptographic tag and switches the flow into an existing CITP session.

## What changes

The CITP levels above the carrier are **unchanged**: `RESOLVE`, `OPEN_AUTH`,
mux, Policy Engine, Anti-SSRF, `MigrationTicket`, and the AEAD transport all
remain the same. Only the bottom carrier changes: instead of a direct
connection to the node IP, the client's observable flow looks like HTTPS to a
decoy origin.

## Why it is a stub

This carrier requires infrastructure **on the path of traffic**:

- a cooperative ISP, or controlled transit, or
- hosting/peering with the ability to observe and redirect decoy flows,
- a decoy origin that terminates real TLS.

Without such a station the carrier intentionally remains a stub. On a plain VPS
this mode does **not** work and is not advertised as a usable mode.

## Where it would plug in

In the tree, this maps to a new `Carrier` implementation under
`internal/chameleon/carrier.go` (see §3.4 of the README) — a `RefractionCarrier`
satisfying the existing `Carrier` interface, wrapping the standard
`RESOLVE`/`OPEN_AUTH`/mux path with a decoy-TLS outer transport and an
on-path tag validator. The Control Fabric (see `protocol/control-fabric.md`)
would provide the bootstrap signal that tells the client which decoy origin
and tag profile to use for the current epoch.

## Safety

The on-path station and decoy origins must be operated lawfully and within
infrastructure the operator controls or is authorised to use. The Control
Fabric's `ErrRequiresInfrastructure` invariant applies: any operation requiring
on-path positioning returns that error unless an authorised backend is wired.
