# KS research integration — 2026-09-08

## What is integrated
- Native regression TestKSResearchLengthContract: 16 public seeds x lengths0..1500, Seal=input+28, exact roundtrip. No sockets or exported keys.
- TestKSResearchScheduleRegression: the fixed R1 public corpus, burn2048+measure8192, terminal1024, fixed4=0/32 and alternate4=32/32 exact equality. Finite noiseless observation, not a universal theorem.
- Public embedded fixture; corrected overstrong comments in map.go. Arithmetic, key schedule, wire format and production parameters are unchanged.
- Reproducible Windows x64 client packaging with no secrets; native Windows research test executable and core selftest.
- R2 offline quantization/loss lab and a protocol fixed before execution.

## Evidence and limits
R1 raw artifacts: ../research/ks-r1-20260908/README.md and its SHA256.json. Prior RU runs measured 24016/24016 length/roundtrip cases and matching Go/Python hashes over3670016 state integers.
Seal +28 is nonce12+AEADtag16, NOT outer IP overhead. Constant overhead preserves input-length differences under fixed packetization; no DPI classifier was evaluated.
Negative conditional sum is insufficient: all32 fixed4 fields had positive top estimates despite negative sums. For alternate4 the top median was -1.413498 bits/iteration on the16384-step window and terminal RMS0 for all32. Exact observations and synthetic fields are not production keys or a lossy modem channel.
Smooth finite-time Lyapunov estimates along Q16.48 orbits do not establish finite-state asymptotic entropy or crypto security. KS uses a local key schedule, not the receiver observer. Synchronization improvements are not automatically traffic-hiding improvements.

## Run
`go test -count=1 ./internal/chaossync -run 'TestKSResearch|TestKsGoldenVector' -v`
`go run ./research/ks-r2-20260908/channel_lab -fields internal/chaossync/testdata/ks_r1_fields.json -out /absolute/new/research/output`
Run final experiments on RU with explicit limits and a private network namespace. Do not run research against production endpoints.
`bash scripts/build-ks-windows.sh /absolute/new/windows-directory`
Build dependencies must already be cached; build is offline and does not deploy or change CURRENT.

## Prior art
- Pecora and Carroll,1990: https://pubmed.ncbi.nlm.nih.gov/10042089/
- Time-varying coupled-map topology,2008: https://link.springer.com/article/10.1140/epjb/e2008-00023-3
- Metadata vs confidentiality,FEP2024: https://arxiv.org/html/2405.13310v2
A missing exact search match is only candidate originality, not established priority.

## Rollback
Before-state archives and manifests exist separately on MCP and RU in their ks-integration-20260908-01 backup directories. Restore uses that host's own archive: agent.md histories differ. The rollback helper requires --apply and a matching post-change checksum; otherwise it refuses. No service restart is part of rollback.

## Final verified packaging and R2 archive (2026-09-09)

RU unit `ks-package-20260908` завершился успешно: `Result=success`, `ExecMainStatus=0`, `ActiveState=inactive`.

Подтверждённые архивы:

- `/root/build/ks-integration-20260908/ks-windows-client-20260908-research.zip`
  - SHA256 `3d61b8c02ccc6a05fb74d4bd20ac384ea0aa4e79e716361a4c823d651f3af2ed`
  - размер `9346290` байт
- `/root/build/ks-integration-20260908/KS-R2-RU-2026-09-08.zip`
  - SHA256 `c1a13c2c1a8e88e1c0f205373ea10a47516b6c121b4089f30d96ac015c4fa4f5`
  - размер `93496` байт

Зеркальные копии на MCP:

- `/files/VPN/dist/ks-windows-client-20260908-research.zip`
- `/files/VPN/dist/KS-R2-RU-2026-09-08.zip`

Отдельно подтверждено:

- `windows-bundle/SHA256SUMS`: 34/34 OK
- `research-deliverable/SHA256SUMS`: 36/36 OK
- в итоговых ZIP не найдены `.key`, `client.json`, `ssh_*` и пути `bin/data/`

Это не является подтверждением обхода DPI/ТСПУ, не доказывает криптографическую стойкость и не заменяет тесты на реальном Windows или реальном транспорте.
