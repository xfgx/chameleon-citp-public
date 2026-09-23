# Анти-DPI: процессы проверки (2026-09-09)

Документ фиксирует интеграцию анти-DPI исследований в процессы репозитория:
что проверяется, как запускать, где лежат результаты и ссылки на разборы в
Notion. Принцип честности из исследований сохраняется: симуляция ≠ измерение
реального ТСПУ; NMSE ≠ совпадение ключей; новизна — только со статусом
«СПЕКУЛЯТИВНО — ВОЗМОЖНО НОВОЕ».

## 1. Что интегрировано

| Компонент | Путь | Назначение |
| --- | --- | --- |
| Регрессионная батарея | `scripts/antidpi-verify.sh` | 6 шагов проверок, exit≠0 при FAIL |
| Вендоренная симуляция | `research/antidpi-sim8/` | sim8.py + baseline JSON/лог свипа 2026-09-09 |
| CI workflow | `.github/workflows/antidpi-verify.yml` | python-батарея + go test chaossync/chameleon + vet |
| Этот документ | `docs/ANTIDPI-PROCESSES-20260909.md` | Описание процесса |
| Бекап старого слоя | `backups/antidpi-20260909T190500Z/` | astra/ + scripts/docs/protocol/workflows + sha256-манифест репо |

Шаги батареи: (1) py_compile sim8; (2) свип EMB_CADENCE=3..6 с побитовым
сравнением JSON против baseline; (3) selftest `protocol/reference_parser.py`;
(4) валидация `internal/chaossync/testdata/ks_r1_fields.json` (32 фикстуры);
(5) статические инварианты (`ksWindow = 8192`, HMAC-SHA256 FrameTag в cst.go,
wire `nonce‖ct`); (6) инвентарь Test-функций (baseline: chaossync 58,
chameleon 138, research+experiments 35; рост разрешён, падение — FAIL).

## 2. Как запускать

На RU-ноде (фон, по образцу astra-процессов):

```bash
cd /files/VPN
nohup bash scripts/antidpi-verify.sh > /files/astra/antidpi-verify.log 2>&1 &
echo $! > /files/astra/antidpi-verify.pid
tail -n 40 /files/astra/antidpi-verify.log
```

В CI — автоматически по push, затрагивающему `research/antidpi-sim8/**`,
`internal/chaossync/**`, `internal/chameleon/**`, `protocol/reference_parser.py`,
либо вручную через workflow_dispatch.

## 3. Известные ограничения стенда (2026-09-09)

- На ноде нет Go; установка go1.26.3 упирается в диск (свободно ~332 МБ из
  8.7 ГБ, видимых файлов ~267 МБ — объём занят вне видимой части устройства).
  До освобождения места go test запускается только в CI.
- `go build ./...` ломают: пустой `cst-staging/internal/chameleon/continuity.go`
  и смешанные пакеты main/chaossync в `experiments/ks-recovery-20260908-v1/v2`
  (файлы built-*.go рядом с исходными).
- Standalone `astra/sim8-result.json` — артефакт прежней версии скрипта
  (top5_chaos, PRF D=0.113); эталон — свип baseline в `research/antidpi-sim8/`.

## 4. Связанные страницы Notion (база Skills)

- Сводная: https://app.notion.com/p/c327dc056904832fa8d5014b84cd185f
- Что реализовано на RU-ноде + проверки: https://app.notion.com/p/c327dc056904833d92a3c4be9a87a3ff
- Пункт 8 углублённо: https://app.notion.com/p/c327dc0569048317b401e79a303f446b
- N1 причинный разрез: https://app.notion.com/p/c327dc056904830bb6dbd9b47426ff0c
- N2 инвариантный вход: https://app.notion.com/p/c327dc056904839788b0e2b197a31444
- N3 наблюдательный ABI: https://app.notion.com/p/c327dc05690483ef95aff6d1e3b53547
- N4 автономное завершение CITP: https://app.notion.com/p/c327dc05690483ca8d2cc798b461b2aa
- N5 сертификат невозможности: https://app.notion.com/p/c327dc0569048333bda2ce58ddd772b9
- N6 причинные свидетели: https://app.notion.com/p/c327dc056904834e89a5c57be6c8f39f
- N7 стираемый граф связности: https://app.notion.com/p/c327dc056904836790dcf1999b47ee39
- Тест sim8 (методология, результаты, воспроизведение): https://app.notion.com/p/c327dc056904834eab6fc7929fb5f5d0

## 5. Что дальше по процессу

1. Освободить диск на ноде → локальный `go test ./internal/chaossync ./internal/chameleon -count=1`.
2. Починить `cst-staging` (пустой continuity.go) и растащить built-*.go в experiments.
3. Риски из разбора репо (`astra/repo-study-20260909.md`, копия в бекапе): fail-open allowlist, peer-learning до AEAD в cdt-socks, прямой egress, гонки map — завести как задачи и гонять батарею после каждого фикса.
