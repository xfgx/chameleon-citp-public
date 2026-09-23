import sys
nl = chr(10)

# ---------- CDT.md: §8 -> статус полной формы ----------
p = 'docs/CDT.md'
s = open(p, encoding='utf-8').read()
old8 = nl.join([
'## 8. Что осталось для полной формы',
'',
'- Непрерывный туннель через ротацию эпох (geometry+ключи мутируют по T, обе стороны в ногу; straddle на границе).',
'- CST-идентичность туннеля поверх эфемерных фрагментов.',
'- Автопилот: авто-подбор степени дисперсии по замерам DPI-профайлера.',
'- Data-plane поверх реального IP-трафика (TUN↔CDT мост) — несёт настоящий серфинг/видео.',
'- Мульти-IP дисперсия (нода держит блок адресов, не только портов) — опция развёртывания.',
'- Полевой DPI-замер несвязуемости против реального ТСПУ.',
''])
assert old8 in s, 'CDT.md §8 anchor'
new8 = nl.join([
'## 8. Статус полной формы (обновлено 2026-09-01)',
'',
'Сделано и закрыто тестами на RU-ноде (`go test ./internal/chaossync` — зелёный):',
'',
'- **Непрерывный туннель через ротацию эпох** — ротационные Fragmenter/Defragmenter, epochSink cur/prev со straddle на границе, глобальный seq непрерывен сквозь ротации (TestCDTRotationMultiEpoch). Живой инстанс под systemd: `cdt-socks-node.service` на RU-ноде.',
'- **CST-идентичность туннеля** — `cdt_cst.go`: AAD фрагмента = sid эпохи направления (KDF от master, `cdt-cst-v1`; на провод не уходит, формат `nonce‖ct` неизменен), `TunnelID` для журналов обеих сторон. Replay/cross-epoch правила покрыты `TestCDTCst*`: straggler границы принимается в окне straddle, повтор и забытая эпоха — отбрасываются.',
'- **Автопилот дисперсии** — `RiskFromMetrics` + `ClassStepper` (гистерезис ±1, dwell 2 эпохи) + in-band REQ/ACK переключение класса на границе эпохи с lockstep обеих сторон (`cdtstream`; потерянный REQ переоформляется с новым fromEpoch — `TestStreamGeomAuto*`). Флаг `-geomauto` в cdt-socks (конверт приёма до 512 портов); точка подачи полевого риска — `Stream.SetExtRisk`.',
'- **TUN↔CDT мост** — доказан ранее (§9); `cmd/cdt-vpn` досинхронизирован в каноническое дерево и собран на RU-ноде.',
'',
'Осталось (инфраструктура и поле — за владельцем):',
'',
'- Мульти-IP дисперсия (нода с блоком адресов, не только портов) — опция развёртывания.',
'- Полевой DPI-замер несвязуемости против реального ТСПУ (сеть владельца) → подача в `SetExtRisk`.',
'- Wintun-порт TUN-моста (`tun_windows.go`) + живой Windows-прогон.',
''])
s = s.replace(old8, new8, 1)
open(p, 'w', encoding='utf-8').write(s)
print('CDT.md patched')

# ---------- CHAOSSYNC.md: обновление про деплой и живую ротацию ----------
p = 'docs/CHAOSSYNC.md'
s = open(p, encoding='utf-8').read()
add = nl.join([
'',
'---',
'',
'## Обновление 2026-09-01 — продакшн-деплой и живая ротация',
'',
'- `chaossync-server` переведён под systemd на RU-ноде: `chaossync-server.service`, порт 4500, те же параметры (T=8, c=0.85, rate=1000, S=32, batch=4), `Restart=always`; rollback-бинарь `/root/build/chaossync-server.rollback-20260901`. Бинарь собран из актуального дерева `/root/vpn` (см. `dist/cdt-chaos-20260901/SHA256SUMS`).',
'- **Живой прогон ротации ключа/расписания** (пункт из открытых остатков): клиент на ноде → `127.0.0.1:4500`, ~60 с при T=8с — захват за 1.38 с, кадр прошёл сквозь множество ротаций эпох (эпохи 223533266→223533283), `frames_ok=1`, `resyncs=0`, `frames_bad_tag=0`, `frames_bad_crc=0` (метрики сервера). Первый прогон на 26 с дал `frames_ok=0` — артефакт длительности (600 бит кадра при rate=1000/S=32 ≈ 19–20 с на плечо; эхо не успевало), не регрессия: ни одного отброшенного кадра.',
'- Остаются за владельцем: bare-metal Windows selftest (`chaossync-selftest.exe` из `dist/cdt-chaos-20260901`, сверка с золотым хэшем Э1) и полевой Э6 против живого DPI.',
''])
open(p, 'a', encoding='utf-8').write(s if False else add)  # append-only
print('CHAOSSYNC.md appended')

# ---------- agent.md: запись о работе (append-only) ----------
p = 'agent.md'
entry = nl.join([
'',
'### 2026-09-01T12:45Z — CDT: полная форма (CST, автопилот дисперсии), chaossync-server и cdt-socks под systemd, полная сборка на RU-ноде',
'',
'- ТЗ владельца: «нам надо все это реализовать; все компиляции — на RU-ноде (все бинари)».',
'- ОКРУЖЕНИЕ: каноническое свежее дерево — /root/vpn (НЕ /root/vpn-new — то старое, до раундов 5+6 включительно). cmd/cdt-vpn существовал только в MCP-копии — досинхронизирован на ноду (3 файла), go vet + build чисты. В MCP-контейнере переустановлен paramiko (преемлемо на диске 97%; бинари в контейнер НЕ тянем).',
'- CDT CST (internal/chaossync/cdt_cst.go, новый): AAD фрагмента = sid эпохи направления (epochSeed(master, cdtLabel("cdt-cst-v1",dir), epoch)[:16]); формат на проводе не меняется (nonce‖ct); включён во всех ротационных конструкторах (NewRotating*/NewStream), burst/lab (NewFragmenter/NewDefragmenter) оставлен без CST для совместимости ранних тестов. TunnelID(master,dir) — стабильный отпечаток туннеля для журналов. cdt.go: поля cst/aad у Fragmenter/epochSink, TickEpoch пересчитывает AAD на ротации. Тесты cdt_cst_test.go (4): чужой master отброшен; lab-фрагмент без CST не проходит в CST-туннель (та же эпоха/ключ — отличается только AAD); straddle: запоздалый фрагмент принят, повтор — отброшен, забытая эпоха — отброшена; TunnelID стабилен/различителен.',
'- CDT автопилот дисперсии: cdt_autopilot.go += RiskFromMetrics (max: dpiRisk, retx×4, (rtt-1)/2), RiskClass (4 класса), AutopilotGeomClass (Dir/PortBase/MinFrag/MaxFrag сохраняются; PortCount≤1 — NAT-дыра — не расширяется), ClassStepper (первая калибровка сразу, далее ±1 класс не чаще dwell=2 эпох). cdtstream.go += in-band протокол переключения класса: REQ{class,fromEpoch}/ACK{class,fromEpoch,ok} control-кадрами с магией \\xffCDTG (приложению не отдаются; seq+ретрансляции надёжного потока бесплатны); приёмник принимает только fromEpoch ∈ [cur+1, cur+16] (sink нового класса создаётся до границы — позиции nonce выровнены); sender переключается только после ok=1; 5 неподтверждённых попыток — честное отключение автопилота (geomAuto=false). Fragmenter/Defragmenter += SetGeomProvider (консультация на границе эпохи; провайдер обязан сохранять Dir). cdt-socks += флаг -geomauto (при listenCount>1 конверт приёма расширяется до 512 портов — ширина класса 3). Тесты cdt_geomauto_test.go (5 функций): юниты риска/классов/гистерезиса; lockstep-переключение 0→3 со сборкой 10 КБ после границы; потеря первого REQ (проглочен после stream-ACK) → таймаут → переоформление → сходимость без рассинхрона.',
'- Проверки на RU-ноде после всех правок: gofmt -l чист (internal/chaossync, cmd/cdt-socks), go vet чист, go test ./internal/chaossync -count=1 → ok 3.364s (базис до правок был 3.626s).',
'- SYSTEMD (RU-нода): chaossync-server.service — голый процесс с Aug30 остановлен, юнит active, :4500 слушается, метрики 127.0.0.1:19090 живы; бинарь пересобран из /root/vpn (sha256 b0d0ea0fc946… для /root/build/chaossync-server); rollback /root/build/chaossync-server.rollback-20260901. cdt-socks-node.service — голый процесс с Aug31 остановлен, юнит active, 48 слушателей 20000-20047; rollback /root/build/cdt-socks.rollback-20260901. cham-server и cham-bcp38-receiver НЕ трогались.',
'- ЖИВАЯ РОТАЦИЯ chaossync (закрыт открытый остаток): клиент → 127.0.0.1:4500, ~60с при T=8с: sync+фаза за 1.38с; кадр 19Б прошёл сквозь множество ротаций эпох (эпохи 223533266→223533283 по метрикам сервера), frames_ok=1, resyncs=0, frames_bad_tag=0, frames_bad_crc=0. Прогон на 26с дал frames_ok=0 — артефакт длительности (600 бит кадра ≈ 19-20с/плечо при rate=1000/S=32), не регрессия.',
'- СБОРКА (все бинари на RU-ноде, Go 1.26.3, -trimpath -ldflags "-s -w", CGO_ENABLED=0): /root/dist/cdt-chaos-20260901 — 16 артефактов (chaossync-server/client/selftest + cdt-server/client/socks/probe по linux+windows; cdt-tun/cdt-vpn linux-only до Wintun-порта) + SHA256SUMS, BUILD_FAIL=0, хэши различны. Бандлы обновлены: bundle-cdt (cdt-probe linux+windows), bundle-cdt-socks (cdt-socks linux+windows). ВАЖНО: с включением CST старые cdt-клиенты с новой нодой несовместимы — клиенту ставить бинарь из dist/cdt-chaos-20260901 / обновлённого бандла.',
'- НЕ СДЕЛАНО (честно): (1) федеративная загрузка GradStats клиент→борд + применение к суррогату в chamd — следующий отдельный этап; направление дизайна: клиент шлёт citp-gradstats как control-кадр ноде, нода (у неё токен записи воркера) батчит и публикует, клиенты читают объединённые статистики через broadcast-каналы и применяют к локальному суррогату; (2) мульти-IP дисперсия — за инфраструктурой владельца; (3) полевой DPI-замер несвязуемости и подача риска в Stream.SetExtRisk — сеть владельца; (4) tun_windows.go (Wintun) и живой Windows-прогон CDT-VPN на ПК владельца; (5) bare-metal Windows selftest chaossync (chaossync-selftest.exe из dist/cdt-chaos-20260901, сверка с золотым хэшем 29f2315f…).',
''])
open(p, 'a', encoding='utf-8').write(entry)
print('agent.md appended')
print('PATCH_DOCS_DONE')
