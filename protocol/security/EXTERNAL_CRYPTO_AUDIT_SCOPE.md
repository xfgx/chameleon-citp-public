# External cryptographic audit scope

Status: **prepared, not independently audited**. The audit must be performed by
a reviewer who did not author these changes. No internal review may be described
as an external audit.

## In scope

- `internal/chameleon/handshake.go`: X25519, HKDF labels, transcript binding,
  authentication, timestamp and replay behavior, blackhole distinguishability.
- `internal/chameleon/transport.go`: AES-GCM key direction, nonce lifecycle,
  framing, masking synchronization and failure behavior.
- `internal/chameleon/drbg.go`, `mask.go`, `shaper.go`: separation of mask streams
  and interactions with transport framing.
- `internal/chameleon/citp_object.go`, `resolver.go`, `migration.go`: canonical
  encoding, HMAC coverage, expiry, replay and cross-session binding.
- `internal/chameleon/mux.go`, `policy.go`: authorization before every egress
  OPEN, resource exhaustion and concurrent state transitions.
- `protocol/reference_parser.py`: independent parser agreement.

## Questions the auditor must answer

1. Can any AEAD key/nonce pair repeat, including after reconnect or counter wrap?
2. Are send/receive keys and mask streams separated in every role?
3. Does the transcript bind both ephemeral keys, client identity and server reply?
4. Can malformed input cause allocation amplification, panic, parser ambiguity or
   inconsistent Go/Python interpretation?
5. Can replay-cache eviction, clock skew or concurrency admit a replay?
6. Can any legacy, UDP, DNS-bound, CITP or resume path bypass egress policy?
7. Is blackhole behavior observably different for invalid-format, invalid-tag,
   unknown-client and replay cases?
8. Are migration and resolution objects bound to the intended session and scope?
9. Are secrets retained in logs, crash dumps, archives or release artifacts?
10. Which claims in README/protocol documentation exceed what the code proves?

## Required deliverables

- commit hash and exact tree audited;
- threat model and assumptions;
- findings with severity, exploit preconditions and affected lines;
- test vectors or proof-of-concept for every confirmed finding;
- remediation review and signed final report;
- explicit list of out-of-scope components.

## Acceptance gate

Production cryptographic-audit status remains `PENDING` until an independent
report and remediation verification are stored next to this file. Passing unit,
fuzz, race or formal-model tests is not a substitute for external review.
