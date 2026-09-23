import sys

# --- 1) README.md: строка chaossync в матрицу зрелости после Refraction ---
pr = 'README.md'
lines = open(pr, encoding='utf-8').read().split(chr(10))
row = '| **chaossync транспорт (хаос-синхронизация, Э0–Э7)** | ✅ | ✅ | ✅ (`docs/CHAOSSYNC.md`) | ✅ (Э6 curves) | 🟡 Self | 🟡 Draft |'
out = []
done = False
for ln in lines:
    out.append(ln)
    if not done and 'Refraction networking (TapDance-class)' in ln:
        out.append(row)
        done = True
if not done:
    print('README anchor MISS')
    sys.exit(1)
open(pr, 'w', encoding='utf-8').write(chr(10).join(out))
print('README.md: chaossync row added')

# --- 2) agent.md: append-only запись ---
pa = 'agent.md'
nl = chr(10)
entry = [
    '',
    '### 2026-08-30T18:05Z — chaossync: транспорт на синхронизации нестационарного ключевого хаос-потока (Э0–Э7)',
    '',
    '- ТЗ владельца: сеть как синхронизация двух хаотических осцилляторов (Windows-клиент ↔ Linux RU-нода); по проводу только скалярный шумоподобный сигнал; f_k мутирует по ключевому расписанию с периодом T против return-map/delay-embedding реконструкции; два участника, без релеев; этическая граница — только собственная динамика, без отравления измерителей цензора.',
    '- НОВЫЙ пакет internal/chaossync: fxp Q16.48 (math/bits, знаковая коррекция), 8-сайтовая CML-логистическая решётка, само-валидирующийся DeriveField (пробник сходимости, перерисовка), провод uint16 BE без заголовков, CSK-модем (±δ на драйв-сайте), rep3-FEC с блочным перемежением, счётчик-управляемая граница эпохи + грейс desync-сторожа, джиттер-буфер с локальными часами (EnqueueDatagram/TickRx), fail-closed ServerMux, cst.go (identity-continuity). Точки входа: cmd/chaossync-server, cmd/chaossync-client, cmd/chaossync-selftest, tools/chaossync-lab.',
    '- Переиспользование Э0 (не переписывалось): DRBG internal/chameleon/drbg.go; образец расписания cf_schedule.go; session-seed HKDF handshake.go; ключи keys.go; MockCensor (у нас сигнал-слой, у них HTTP-слой — задокументировано); автопилот cmd/chamd/autopilot.go (новая роль: выбор T/c как живой trade-off); DPI-профилер cf_profiler.go (новая роль: качество канала для sync). CST-файл в cst-staging был 0 байт — реализован заново.',
    '- Результаты по этапам: Э1 детерминизм — золотой хэш 29f2315f353442c2bdd8183ad6d175dcd749929d4b095a6ab4cb6461d2ac5557 (Linux native == Windows PE под wine); Э2 sync на идеальном канале (захват ~15 датаграмм, остаток <4e-4, чужой ключ не sync); Э3 BER окна 0.00000 без клиппинга, кадр через границы эпох (roundtrip BER 1/341); Э4 мутация без разрыва логической сессии (3/3 кадра, resyncs=0); Э5 РЕАЛЬНЫЙ cross-border UDP Myserv(198.51.100.10)→RU(192.0.2.10:4500): sync+фаза за 6.2с, эхо кадра получено, resid 1.4e-5, loss=0, resyncs=0, jitter 0.5мс; открытые inbound-UDP через firstbyte: 123/500/443/4500/51820/853/1194.',
    '- Э6 (новизна, числа в docs/e6/): recon — стационарное поле NMSE≈0.0000 на всех окнах (атакующий реконструирует тривиально), мутирующее поле NMSE 0.02–2.1 нестабильно (реконструкция срывается); mutate — при потерях ≤1% catchup=64 датаграммы, ≥5% перезахваты доминируют. Вердикт: T-gap СУЩЕСТВУЕТ (T≈200–1600 сэмплов = 1–8с: sync держится, реконструкция срывается).',
    '- Корневые причины при отладке (все закрыты): не-конвергенция части полей → само-валидация DeriveField; сдвиг битового потока на границах → счётчик-управляемый переход (детерминированно, как TX); ложные перезахваты на пограничном транзиенте (≤2 окон) → грейс syncWinK·S; ложные потери от джиттера тикера → джиттер-буфер, поле шагает ТОЛЬКО по реальным сэмплам (пустая очередь=джиттер, не потеря).',
    '- Сборка на RU-ноде (CGO_ENABLED=0 GOOS=windows GOARCH=amd64 -trimpath -ldflags=-s -w): chaossync-client-windows-amd64.zip = sha256 6db512e35afd8220ebe264bfcdb3dd7cbbc1d42369cdc8cc3f69e60a3558810e (3789651 Б; client.exe + selftest.exe + client.conf + README-RUN.txt). wine-selftest → золотой хэш совпал.',
    '- Тесты на RU-ноде: gofmt/vet чисто; go test ./internal/chaossync -count=1 → ok 2.2s (после зачистки отладочной инструментации и временных тестов). Отчёт docs/CHAOSSYNC.md; матрица зрелости README §7 дополнена.',
    '- НЕ СДЕЛАНО (честно): (1) запуск на голом железе чистой Windows (только wine на RU; финальный самотест — chaossync-selftest.exe на стороне пользователя); (2) Э6 в поле против реальной цензуры на длинных дистанциях (снято эмуляцией + cross-border sync, не против живого DPI); (3) продакшн-деплой chaossync-server как systemd-unit (тесты на отдельном порту 4500, прод cham-server НЕ трогали); (4) живой прогон ротации ключа/расписания (задокументирована в README-RUN.txt, не прогнана вживую).',
]
s = open(pa, encoding='utf-8').read()
if not s.endswith(nl):
    s += nl
open(pa, 'w', encoding='utf-8').write(s + nl.join(entry) + nl)
print('agent.md: entry appended')
