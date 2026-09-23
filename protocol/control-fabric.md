# Control Fabric — CAR / BGP / CDN control channels

Status: **experimental, safe-stub layer**. Spec version: CITP v2.1.

The Control Fabric adds ultra-narrow **control** channels to CITP. These
channels carry **only** bootstrap / carrier-profile switch / next-entry
selection / fallback / session-recovery signaling. The main VPN payload stays
on the existing data-plane (mux + carrier). Control Fabric never carries
payload.

## Channels

| Channel | File | Direction | Carries | Status |
|--------|------|-----------|---------|--------|
| CDN cache-state board | `cf_bulletin.go` | bidir | encrypted control frames (primary) | **real TLS** (self-signed, local), lab-scoped |
| DNS beacon | `cf_dns.go` | node→client | short metadata beacon | local authoritative zone; **real DoH reader** (`cf_doh.go`) |
| CAR (censor-as-modulator) | `cf_car.go` | node→client | 1-bit verdict signaling | lab (benign token + MockCensor); **real block-page signature detection** |
| BGP control-plane | `cf_bgp.go` | node→client (read) | entry liveness / AS-path | **real RIPEstat** (`prefix-overview` + `routing-history`) |

Reference data (`cf_reference.go`): real public DoH endpoints (Cloudflare,
Google, Mullvad, Quad9) and real popular decoy origins (VK, Yandex, Google,
YouTube, GitHub, …) used as cover traffic — all real internet data, no secrets.

## Crypto

Mirrors the CITP core:
- `DeriveSessionSecret(seed)` — HKDF-SHA256, 32 bytes (`cf_crypto.go`).
- `AEADEncrypt/AEADDecrypt` — ChaCha20-Poly1305, layout `nonce(12) || ct`.
- `HMACSession(key, data)` — HMAC-SHA256 for AuthTag-style signatures.

Control messages are `length-prefixed → chunked into 180-byte pieces → AEAD-encrypted`
(`cf_framing.go`, `EncodeControlMessage` / `DecodeControlMessage`).

## Real vs local (this build)

- **Real (live internet, no local dependency):** DoH TXT resolution against
  Cloudflare 1.1.1.1; BGP AS-path + routing-history via RIPEstat
  (`prefix-overview`, `routing-history`) with a beacon snapshot (stable hash of
  AS-path state for change detection).
- **Local (own servers only):** node bulletin (real self-signed TLS, store &
  forward), node authoritative DNS TXT zone, node CAR verdict channel, and the
  lab `MockCensor` (on-path model). All marked `LOCAL DATA`.
- **Stubs (need infrastructure that is not local):** BGP `Announce`/`Withdraw`
  (return `ErrRequiresInfrastructure`), foreign-CDN priming, real on-path
  censor station against foreign DPI.

1. **No payload on the Control Fabric.** `MaxControlMessage = 1024` bytes.
2. **Operations needing real infrastructure return `ErrRequiresInfrastructure`:**
   - `BGPControlChannel.Announce` / `Withdraw` (need lawful AS/prefix control),
   - foreign-CDN cache priming (need owned CDN),
   - real censor triggering against foreign DPI (need on-path station).
3. **Local data is in-memory only.** Every in-memory store is marked
   `LOCAL DATA` in the source. State is lost on restart.
4. **CAR trigger is a benign token** (`FORBIDDEN_TOKEN`), never real banned
   keywords/SNIs. Real censor triggering depends on the actual on-path DPI rule
   set and is environment-specific.
5. **DNS beacon is rate-limited and short** (≤180 bytes per label) and always
   answers (empty TXT) to avoid NXDOMAIN negative caching.

## Lab flow (`tools/cham-controlfab`)

Node publishes a control message (e.g. `next-entry=…;profile=…`) across the
CDN board, a DNS beacon, and CAR bits. Client recovers it via the CDN board,
reads the DNS beacon, reads CAR verdict bits, and does a read-only BGP lookup.

## Deployment constraints (documented, not hidden)

- CDN board: in a real deployment this is short HTTPS to a legitimate-looking
  host / object storage with rotating keys. Lab uses localhost.
- DNS beacon: real constraints — TXT payload ≤255 bytes per string, UDP 512B
  cap, TTL/caching, NXDOMAIN negative caching. Rotating labels + TTL=1 limit
  caching.
- BGP write: requires lawful control of an AS and a globally routable prefix.
  Uncontrolled route flapping destabilises global routing — never use in prod.
- CAR: the on-path censor is the deployment's DPI; the lab uses `MockCensor`
  (`cf_mock_censor.go`, TEST/LAB ONLY — not in production).
