import sys
nl = chr(10)

# ---------- 1) docs/KS.md — новый документ дизайна ----------
ksmd = nl.join([
'# KS — data-plane на keystream-инверсии ядра chaossync',
'',
'Статус: **ядро + драйвер + живой прогон + продакшн-деплой**. Дата среза: 2026-09-01.',
'Код: `internal/chaossync/ks.go` + `cmd/ks-vpn`. Заменяет CDT в роли data-plane',
'(CDT снят с роли; код и документ CDT оставлены как лабораторная справка — идеи',
'CST и ротации переиспользованы здесь).',
'',
'> Carrier-режим chaossync (CSK / Pecora–Carroll / S=32) **не тронут** — он остаётся',
'> control-plane (мелкие команды: ротация мастера, ip/port-геометрия, тайминги).',
'',
'## 1. Идея (инверсия)',
'',
'В carrier-режиме решётка — носитель, идущий по проводу (медленно: физика',
'синхронизации). В KS решётка — **локальный генератор keystream на обеих',
'сторонах**; по проводу идёт только `nonce‖ct`. Ключ никогда не передаётся.',
'',
'- Та же 8-сайтовая CML-решётка Q16.48, те же `DeriveField` (само-валидирующийся)',
'  и `EpochInit` эпохи — переиспользованы из `map.go`/`schedule.go` без изменений;',
'  гейт Э1 и золотой хэш `29f2315f…` покрывают этот путь.',
'- Направления разделены `dirMaster`: c2n и n2c — независимые генераторы.',
'- Датаграмма c эпохи m: `k_c = SHA-256("ks-whiten-v1" ‖ c ‖ state_c)` — ключ',
'  ChaCha20-Poly1305 (дефолт; AEGIS-128L заявлен опцией — пока честный stub,',
'  в x/crypto проверенной реализации нет).',
'- `nonce_c = SHA-256("ks-nonce-v1" ‖ k_c)[:12]` — на проводе: маркер позиции,',
'  ничего не раскрывает.',
'- AAD = sid эпохи направления (`epochSeed(master, "ks-cst-v1"-dir, m)[:16]`) —',
'  CST-идея: выводится локально, на проводе не появляется.',
'',
'## 2. Свойства по построению',
'',
'- **Потеря не рвёт состояние**: решётка шагает по счётчику, не по прибытию.',
'  Потерянная датаграмма = потерянный IP-пакет; следующая расшифровывается.',
'- **Replay-окно**: приёмник держит скользящее окно ожидаемых позиций (8192)',
'  nonce→key; поглощённый nonce изымается (повтор отброшен); граница эпохи —',
'  straddle cur/prev (запоздалая датаграмма прошлой эпохи принимается один раз,',
'  забытая эпоха — никогда).',
'- **Ротация эпох бесплатная**: граница по общему счётчику времени (NTP),',
'  без in-band REQ/ACK-налога.',
'- **Probe-invisibility**: датаграмма, не прошедшая AEAD под текущим keystream,',
'  получает ноль ответа; адрес клиента нода учит только от валидных датаграмм',
'  (не от шума сканеров). Снаружи порт неотличим от фильтрованного.',
'',
'## 3. Проверки (все на RU-ноде, Go 1.26.3)',
'',
'- **Бит-идентичность Windows↔Linux**: golden-вектор KS',
'  `c043ccf0075a8ec14523f5a8546151a7e0a9e28de406e0f2e7d13438c5fc70ce` — жёсткий',
'  гейт `TestKsGoldenVector`; `chaossync-selftest` печатает обе строки (carrier Э1',
'  `29f2315f…5557` + KS). Прогон windows-сборки под wine на ноде совпал с linux',
'  побитово (обе строки). Bare-metal Windows — самотестом из архива (за владельцем).',
'- Тесты (`ks_test.go`, все PASS): чужой master → тишина (100/100); потеря каждой',
'  3-й датаграммы — остальные 33/33 расшифровались и совпали; replay в straddle;',
'  ротации ×8 — 200/200; изоляция направлений; AEGIS — честный отказ.',
'- Живой прогон (netns+veth на ноде, `/root/build/ks_ping.sh`): ping через туннель',
'  4/4 (0% loss); 5 активных проб мусором → dropped=5, ноль ответов, туннель жив;',
'  20 пингов при 10% потерь (tc netem) за ~30 с (~4 ротации при T=8с): 16/20,',
'  поток не рвётся.',
'- `go vet` чист (linux и windows), `gofmt` чист; полный пакет `internal/chaossync`',
'  зелёный (carrier не тронут).',
'',
'## 4. Деплой',
'',
'- `ks-vpn-node.service` (RU-нода): TUN ks0 10.99.0.2/24, UDP :51820 (в разрешённом',
'  inbound-списке firstbyte), NAT `ks_nat` (ens3 masquerade 10.99.0.0/24),',
'  ip_forward=1, Restart=always. Ключ `/root/build/ks-vpn.key` (0600, свежий).',
'- `cdt-socks-node.service` выключен (disable --now): CDT снят с роли data-plane.',
'  Откат: unit-файл и бинарь на месте.',
'- `chaossync-server.service` (:4500, control-plane) — без изменений.',
'- Windows-клиент: `/root/dist/ks-windows-client-20260901.tar.gz` (ks-vpn.exe +',
'  wintun.dll + ключ + README + bat). Артефакты: `/root/dist/ks-chaos-20260901/`.',
'',
'## 5. Честный предел и не сделано',
'',
'- `tun_windows.go` компилируется и vet-чист, но живой прогон на Windows-хосте не',
'  выполнялся (нет Windows в среде) — финальный запуск за владельцем.',
'- AEGIS-128L — заявленная опция, не реализована (честный stub).',
'- Полевой прогон RU-клиент ↔ нода через интернет — следующий шаг (живой замер',
'  с ПК владельца; нода слушает 51820/udp и готова).',
'- Control-plane команды для KS (ротация мастера, смена портов) пока вручную —',
'  интеграция chaossync control-plane → KS — следующий этап.',
'- Мульти-IP — как раньше, за инфраструктурой владельца.',
''])
open('docs/KS.md', 'w', encoding='utf-8').write(ksmd + nl)
print('KS.md written')

# ---------- 2) CDT.md: баннер о снятии с роли ----------
p = 'docs/CDT.md'
s = open(p, encoding='utf-8').read()
anchor = '# CDT — Chaos-Dispersed Transport (растворение потока, не маскировка)'
assert s.count(anchor) == 1, 'CDT.md title anchor'
s = s.replace(anchor, anchor + nl + nl +
'> **Статус 2026-09-01: CDT СНЯТ с роли data-plane** — заменён keystream-инверсией ядра chaossync (см. `docs/KS.md`, драйвер `cmd/ks-vpn`, юнит `ks-vpn-node`). Документ и код оставлены как лабораторная справка; CST и ротация эпох переиспользованы в KS.',
1)
open(p, 'w', encoding='utf-8').write(s)
print('CDT.md banner added')

# ---------- 3) agent.md: запись (append-only) ----------
entry = nl.join([
'',
'### 2026-09-01T13:40Z — KS: data-plane на keystream-инверсии ядра chaossync (замена CDT), деплой ks-vpn-node',
'',
'- ТЗ владельца: заменить CDT data-plane на keystream-инверсию; carrier chaossync (CSK/Pecora–Carroll/S=32) не трогать — остаётся control-plane.',
'- НОВЫЙ код internal/chaossync/ks.go: KeyGen — локальный генератор keystream из CML-решётки (DeriveField+EpochInit+dirMaster переиспользованы без изменений; решётка шагает СТРОГО по счётчику, без сетевого драйва/CSK/наблюдателя). whiten: k_c=SHA-256(ks-whiten-v1‖ctr‖state) → ChaCha20-Poly1305; nonce=SHA-256(ks-nonce-v1‖k)[:12] на проводе (маркер позиции). Wire nonce‖ct; AAD=ksCstAAD (epochSeed, ks-cst-v1+dir) — CST-идея сохранена. Sender/Receiver ротационные (T>0) и фиксированные (лаборатория); приёмник — скользящее окно nonce→key (8192) + straddle cur/prev (паттерн epochSink из CDT-ротации). Ротация бесплатная (общий счётчик, без REQ/ACK). AEGIS-128L — честный stub ErrSuiteUnsupported (в x/crypto реализации нет).',
'- Тесты (internal/chaossync/ks_test.go, все PASS; gofmt/vet чисты на linux и windows): golden-гейт KsGoldenVector=c043ccf0075a8ec14523f5a8546151a7e0a9e28de406e0f2e7d13438c5fc70ce (зафиксирован жёстким тестом); потеря каждой 3-й датаграммы не ломает поток (33/33 дошли и сошлись); чужой master → тишина (100/100 отброшено, свой принят); replay в straddle (запоздалая принята / повтор отброшен / забытая эпоха отброшена); ротации ×8 — 200/200 датаграмм; изоляция направлений c2n/n2c; AEGIS-отказ. Полный пакет зелёный (3.858s) — Э1 carrier не тронут (29f2315f… печатается прежним).',
'- chaossync-selftest теперь печатает ДВЕ строки (carrier Э1 + KS golden). Прогон windows-сборки под wine на ноде совпал с linux побитово (обе строки) — бит-идентичность Win↔Linux снята; bare-metal — за владельцем, как раньше.',
'- cmd/ks-vpn (новый драйвер TUN↔KS): один порт на направление, отправка с приёмного сокета (NAT-дыра), probe-invisible (адрес клиента учится только от валидных датаграмм), packet-aligned (1 IP-пакет = 1 KS-датаграмма). tun.go/tun_linux.go ПЕРЕИСПОЛЬЗОВАНЫ из cdt-vpn без изменений (по ТЗ); tun_windows.go — новый, на официальном биндинге golang.zx2c4.com/wintun (уже в go.mod). vet чист на linux И windows; сборки обеих платформ выполнены на RU-ноде.',
'- ЖИВОЙ ПРОГОН (netns+veth на ноде, /root/build/ks_ping.sh): ping через туннель 4/4 (0% loss); 5 активных проб мусором → dropped=5, ноль ответов, туннель жив (контрольный ping 2/2); 20 пингов при 10% потерь (tc netem на vethA) за ~30с (~4 ротации при T=8с): 16/20 дошло — поток не рвётся, счётчики согласованы.',
'- ДЕПЛОЙ: ks-vpn-node.service active на RU-ноде — TUN ks0 10.99.0.2/24, UDP :51820 (в разрешённом inbound-списке firstbyte), NAT ks_nat masquerade ens3, ip_forward=1, Restart=always; свежий ключ /root/build/ks-vpn.key (0600, сгенерирован бинарем, не читался). cdt-socks-node.service disable --now (CDT снят с роли data-plane; откат — unit и бинарь на месте). cham-server.service и chaossync-server.service НЕ трогались.',
'- АРТЕФАКТЫ (все собраны на RU-ноде): /root/dist/ks-chaos-20260901/ (ks-vpn linux+windows, chaossync-selftest linux+windows, SHA256SUMS); /root/dist/ks-windows-client-20260901.tar.gz (4 058 251 Б, sha256 d7adcf969f489ef244ad132ec18937a384cc1553eef08ebb36e78f96c3adb6be): ks-vpn-windows-amd64.exe + wintun.dll + chaossync-selftest-windows-amd64.exe + data/ks-vpn.key (0600, скопирован без чтения/печати) + README.txt + run-ks-vpn.bat + SHA256SUMS. В MCP не переносится (правило владельца). Документ дизайна: docs/KS.md; CDT.md получил баннер о снятии с роли.',
'- НЕ СДЕЛАНО (честно): (1) tun_windows.go не прогнан на живом Windows-хосте (компилируется+vet чист; рантайм — за владельцем); (2) AEGIS-128L не реализован (честный stub — нужна проверенная реализация); (3) полевой прогон с Windows-ПК владельца через интернет (нода слушает 51820/udp и готова); (4) control-plane команды для KS (ротация мастера, смена портов) пока вручную — интеграция chaossync control-plane → KS следующим этапом; (5) CDT-код физически не удалён — оставлен как лабораторная справка (если нужно удаление cmd/cdt-* и cdt-файлов — отдельным шагом по команде владельца).',
''])
open('agent.md', 'a', encoding='utf-8').write(entry)
print('agent.md appended')
print('PATCH_KS_DOCS_DONE')
