# CITP formal state-machine specification

`CITP.tla` is an executable abstract TLA+ model of the security-relevant state machine.
It models authentication, session failure, monotonic nonces, policy-gated OPEN,
stream limits, bounded pending handlers and the DNS cache bound.

Required invariants:

- `TypeOK`
- `OnlyAuthenticatedEstablished`
- `OpenRequiresPolicy`
- `StreamLimit`
- `FailedHasNoStreams`

Example TLC model constants:

```text
Clients = {c1, c2}
StreamIDs = {1, 2, 3}
MaxNonce = 3
MaxStreams = 2
MaxPending = 2
MaxCache = 2
```

Model-checking command after installing TLA+ tools:

```bash
java -cp tla2tools.jar tlc2.TLC -config protocol/formal/CITP.cfg protocol/formal/CITP.tla
```

The model is intentionally an abstraction. Wire parsing, AEAD correctness and
cryptographic assumptions are covered by tests and the external-audit scope.
