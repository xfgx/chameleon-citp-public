# CITP threat model and correctness gates

## Adversary

The adversary may observe, delay, drop, duplicate, reorder and corrupt traffic;
open arbitrary TCP connections to the node; send malformed authenticated frames
from a compromised client; control DNS answers outside the node; and exhaust
connections, streams and queues. Endpoint or node compromise, traffic-correlation
anonymity and denial of all network connectivity are out of cryptographic scope.

## Fail-closed rules

- No egress socket is opened before authentication and one common policy decision.
- Domain egress requires a valid session-bound `ResolutionObject` by default.
- Parser input is canonical: trailing bytes and truncated lengths are rejected.
- AEAD nonce counters never wrap.
- Corruption, loss, duplication and reordering terminate/desynchronize a session;
  they must never deliver unauthenticated plaintext.
- Connections, streams, pending handlers, per-stream queues, DNS cache and strike
  tracking are bounded.

## Current bounds

| Resource | Bound |
|---|---:|
| Server connections | 1024 default, configurable 1..65536 |
| Streams per session | 256 default, policy maximum 4096 |
| Pending OPEN/RESOLVE/RESUME handlers | 64 |
| Stream receive queue | 16 frames |
| Frame plaintext | 65,518 bytes |
| CITP payload | 65,535 bytes |
| DNS cache entries | 256 per session |
| Resolution addresses | 64 decoded / 16 generated |
| OPEN control payload | 2,048 bytes |
| Error payload | 512 bytes |
| Strike entries | 65,536 |
| Stream lifetime | 24 hours default, maximum 7 days |
