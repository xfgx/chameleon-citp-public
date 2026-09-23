# Chameleon CITP — открытый исходный код

> **English version below / Английская версия ниже.**

Полный исходный код проекта **Chameleon CITP (Chameleon Intent Transport Protocol)** — сетевого стека и протокола передачи авторизованных сетевых намерений. Репозиторий содержит всё необходимое для **независимой сборки и установки** всех компонентов: серверной ноды (Linux), клиента Windows (`chamd`), Android-клиента, мобильного ядра (`mobilecore`), утилит и экспериментальных инструментов.

Приватные ключи, пароли, токены и персональные конфигурации из кода удалены и заменены плейсхолдерами `<REDACTED>` — перед запуском сгенерируйте собственные (см. раздел «Ключи и доступ»).

---

## Содержание

1. [Состав репозитория](#1-состав-репозитория)
2. [Требования](#2-требования)
3. [Быстрая сборка](#3-быстрая-сборка)
4. [Установка серверной ноды (Linux)](#4-установка-серверной-ноды-linux)
5. [Клиент Windows](#5-клиент-windows)
6. [Клиент Android](#6-клиент-android)
7. [Ключи и доступ](#7-ключи-и-доступ)
8. [Тесты и проверка](#8-тесты-и-проверка)
9. [Устранение неполадок](#9-устранение-неполадок)

---

## 1. Состав репозитория

| Путь | Что это |
|---|---|
| `cmd/cham-server` | Серверная нода CITP (Linux daemon) |
| `cmd/chamd` | Клиент Windows: TUN (Wintun), SOCKS5, Dashboard, автопилот обхода |
| `cmd/cham-client`, `cmd/cham-keygen`, `cmd/cham-deploy` | CLI-клиент, генератор ключей, деплой-утилита |
| `cmd/ks-*`, `cmd/cdt-*`, `cmd/chaossync-*`, `cmd/probe4hit`, `cmd/chaos-metrics` | Экспериментальные/исследовательские компоненты и транспорты |
| `internal/chameleon` | Ядро протокола: кадры, криптография, carriers, DPI-профайлер, Control Fabric |
| `internal/chaossync` | Внутренний модуль синхронизации |
| `mobilecore` | Go-ядро для Android (собирается через gomobile bind в `.aar`) |
| `android` | Android-приложение (Kotlin, VpnService, Gradle) |
| `tools/` | Утилиты: DPI-профайлер, детекторы, flowstats, citp-sim, wintun и др. |
| `protocol/` | Формальная спецификация протокола и референс-парсер на Python |
| `scripts/` | Скрипты сборки и проверок (`build-release.sh`, `security-check.sh` и др.) |
| `workers/cham-bridge` | Cloudflare Worker для bulletin board (Control Fabric) |
| `docs/` | Документация по деплою, протоколам, исследованиям |
| `packaging/windows` | Скрипты и шаблоны Windows-пакета |
| `experiments/`, `backups/`, `research/` | Исследовательские материалы (не нужны для сборки) |

## 2. Требования

- **Go ≥ 1.26** (см. `go.mod`) — для сервера, клиента и всех утилит.
- **Linux** (для серверной ноды) или Windows/macOS для кросс-сборки.
- Для Windows-клиента: **Wintun** (`tools/wintun`, лицензия прилагается) — `wintun.dll` рядом с `chamd.exe`.
- Для Android: **Android SDK + NDK**, `gomobile` (`go install golang.org/x/mobile/cmd/gomobile@latest`, затем `gomobile init`), Gradle.
- Для Cloudflare Worker (опционально): аккаунт Cloudflare + `wrangler`.

## 3. Быстрая сборка

```bash
# Клонирование и переход в корень модуля
git clone <url-репозитория> chameleon && cd chameleon

# Загрузка зависимостей
go mod download

# Сервер (linux/amd64)
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o bin/cham-server ./cmd/cham-server

# Клиент Windows (windows/amd64)
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o bin/chamd.exe ./cmd/chamd

# CLI-клиент и кейген
go build -o bin/cham-client ./cmd/cham-client
go build -o bin/cham-keygen ./cmd/cham-keygen
```

Все команды в одном скрипте: `scripts/build-release.sh` (собирает linux/windows цели в `bin/`).

Утилиты собираются аналогично, например:

```bash
go build -o bin/cham-profiler ./tools/cham-profiler
go build -o bin/cham-detectors ./tools/cham-detectors
```

## 4. Установка серверной ноды (Linux)

```bash
# 1. Соберите сервер (см. выше) и скопируйте на ноду, например /opt/chameleon/
install -m 0755 bin/cham-server /opt/chameleon/cham-server

# 2. Сгенерируйте ключ ноды (НЕ перезаписывайте существующий!)
/opt/chameleon/cham-server -genkey -keyfile /etc/chameleon/server.key

# 3. Создайте allowlist клиентов (по одному публичному ключу на строку)
install -m 0600 /dev/null /etc/chameleon/clients.txt
cham-keygen -public <публичный-ключ-клиента> >> /etc/chameleon/clients.txt

# 4. systemd-юнит — шаблон в deploy/cham-server.service
install -m 0644 deploy/cham-server.service /etc/systemd/system/cham-server.service
systemctl daemon-reload && systemctl enable --now cham-server
journalctl -u cham-server -f
```

Основные флаги сервера:

| Флаг | Назначение |
|---|---|
| `-listen` | Адрес прослушивания (например `:9443` или `0.0.0.0:8443`) |
| `-keyfile` | Приватный ключ ноды |
| `-allowfile` | Файл с allowlist публичных ключей клиентов |
| `-max-connections` | Лимит одновременных соединений |
| `-cbr`, `-flavor` | Параметры трафик-шейпинга/маскировки |
| `-cf-board-url` | URL bulletin board (опционально); токен записи задаётся через переменную окружения `CITP_CF_BOARD_TOKEN` |

Подробный деплой и безопасное обновление с откатом: `docs/NODE_DEPLOYMENT.md`.

## 5. Клиент Windows

1. Соберите `chamd.exe` (см. выше) или используйте `scripts/build-release.sh`.
2. Положите рядом `wintun.dll` своей архитектуры из `tools/wintun/bin/<arch>/`.
3. Запуск:

```powershell
# TUN-режим (весь трафик системы; требуются права администратора)
.\chamd.exe -tun

# Прокси-режим без прав администратора (SOCKS5 на 127.0.0.1:1080)
.\chamd.exe
```

- Панель управления: `http://127.0.0.1:8080`
- Флаг `-autopilot=false` отключает автопилот обхода (включён по умолчанию).
- Готовые скрипты запуска и самопроверки: `packaging/windows/`.

## 6. Клиент Android

```bash
# 1. Соберите мобильное ядро в AAR
gomobile bind -target=android/arm64 -o android/app/libs/mobilecore.aar ./mobilecore

# 2. Соберите APK
cd android && ./gradlew assembleRelease   # или gradlew.bat на Windows
```

Готовый APK появится в `android/app/build/outputs/apk/`. Минимум — Android 6 (arm64).

## 7. Ключи и доступ

Все секреты из репозитория удалены. Перед запуском создайте свои:

| Что | Как сгенерировать |
|---|---|
| Ключ ноды | `cham-server -genkey -keyfile server.key` |
| Ключ клиента | `cham-keygen` (публичная часть — в allowlist ноды) |
| Токен bulletin board | любая длинная случайная строка; задаётся через переменную окружения `CITP_CF_BOARD_TOKEN` на ноде и в `wrangler.toml` воркера |
| `android/app/src/main/assets/ks-vpn.key` | заменяется ключом вашей установки (см. `packaging/windows/client.example.json`) |

**Никогда не коммитьте** реальные ключи и `.env`-файлы — они исключены через `.gitignore`.

## 8. Тесты и проверка

```bash
go test ./...        # все юнит-тесты
go vet ./...         # статический анализ
bash scripts/security-check.sh   # проверка на случайно закоммиченные секреты
```

Независимый парсер wire-формата: `protocol/reference_parser.py`.

## 9. Устранение неполадок

- **Нода молчит при подключении** — так задумано: на неаутентифицированные запросы нода отвечает 0 байт (защита от активного зондирования). Проверяйте allowlist и ключи.
- **`chamd` не поднимает TUN** — запустите от администратора и убедитесь, что `wintun.dll` рядом с exe.
- **DNS-вердикты «poisoning» без реальной блокировки** — см. разделы про DPI-профайлер в `docs/`, там описаны известные ложные срабатывания и их трактовка.
- Логи ноды: `journalctl -u cham-server -n 100 --no-pager`.

## Лицензия

См. `LICENSE-NOTICE.md`. Код сторонних компонентов (Wintun и др.) распространяется под их собственными лицензиями (`tools/wintun/LICENSE.txt`).

---
---

# Chameleon CITP — Open Source

Complete source code of the **Chameleon CITP (Chameleon Intent Transport Protocol)** project: a network stack and protocol for transporting authenticated network *intents* instead of raw L3 packets. This repository contains everything needed to **build and install all components yourself**: the Linux server node, the Windows client (`chamd`), the Android client, the mobile core (`mobilecore`), utilities, and experimental tools.

All private keys, passwords, tokens, and personal configuration have been removed and replaced with `<REDACTED>` placeholders — generate your own before running (see "Keys and access").

## Repository layout

| Path | What it is |
|---|---|
| `cmd/cham-server` | CITP server node (Linux daemon) |
| `cmd/chamd` | Windows client: TUN (Wintun), SOCKS5, dashboard, censorship-bypass autopilot |
| `cmd/cham-client`, `cmd/cham-keygen`, `cmd/cham-deploy` | CLI client, key generator, deploy utility |
| `cmd/ks-*`, `cmd/cdt-*`, `cmd/chaossync-*` | Experimental/research components and transports |
| `internal/chameleon` | Protocol core: frames, crypto, carriers, DPI profiler, Control Fabric |
| `mobilecore` | Go core for Android (built via gomobile bind into `.aar`) |
| `android` | Android app (Kotlin, VpnService, Gradle) |
| `tools/` | Utilities: DPI profiler, detectors, flowstats, citp-sim, wintun, etc. |
| `protocol/` | Formal protocol specification + independent Python reference parser |
| `scripts/` | Build and security-check scripts |
| `workers/cham-bridge` | Cloudflare Worker for the bulletin board (Control Fabric) |
| `docs/` | Deployment, protocol, and research documentation |
| `packaging/windows` | Windows package scripts and templates |
| `experiments/`, `backups/`, `research/` | Research materials (not required for building) |

## Requirements

- **Go ≥ 1.26** (see `go.mod`) for the server, client, and all utilities.
- **Linux** for the server node; Windows/macOS work for cross-compilation.
- Windows client: **Wintun** (`tools/wintun`, license included) — place `wintun.dll` next to `chamd.exe`.
- Android: **Android SDK + NDK**, `gomobile` (`go install golang.org/x/mobile/cmd/gomobile@latest`, then `gomobile init`), Gradle.
- Optional: a Cloudflare account + `wrangler` for the bulletin-board Worker.

## Quick build

```bash
git clone <repo-url> chameleon && cd chameleon
go mod download

# Server (linux/amd64)
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o bin/cham-server ./cmd/cham-server

# Windows client (windows/amd64)
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o bin/chamd.exe ./cmd/chamd

# CLI client and keygen
go build -o bin/cham-client ./cmd/cham-client
go build -o bin/cham-keygen ./cmd/cham-keygen
```

One-shot script: `scripts/build-release.sh` (builds linux/windows targets into `bin/`).

## Server node setup (Linux)

```bash
install -m 0755 bin/cham-server /opt/chameleon/cham-server
/opt/chameleon/cham-server -genkey -keyfile /etc/chameleon/server.key   # do NOT overwrite an existing key
install -m 0600 /dev/null /etc/chameleon/clients.txt   # one client public key per line
install -m 0644 deploy/cham-server.service /etc/systemd/system/cham-server.service
systemctl daemon-reload && systemctl enable --now cham-server
journalctl -u cham-server -f
```

Key flags: `-listen` (e.g. `:9443`), `-keyfile`, `-allowfile`, `-max-connections`, `-cbr`/`-flavor` (traffic shaping), `-cf-board-url` (optional bulletin board; write token via `CITP_CF_BOARD_TOKEN`).

Full deployment and safe rollback procedure: `docs/NODE_DEPLOYMENT.md`.

## Windows client

1. Build `chamd.exe` (above) or use `scripts/build-release.sh`.
2. Put the matching-architecture `wintun.dll` from `tools/wintun/bin/<arch>/` next to it.
3. Run:

```powershell
.\chamd.exe -tun   # full TUN mode (run as Administrator)
.\chamd.exe        # proxy mode, SOCKS5 on 127.0.0.1:1080, no admin needed
```

Dashboard: `http://127.0.0.1:8080`. Disable the autopilot with `-autopilot=false`.

## Android client

```bash
gomobile bind -target=android/arm64 -o android/app/libs/mobilecore.aar ./mobilecore
cd android && ./gradlew assembleRelease
```

APK output: `android/app/build/outputs/apk/`. Minimum: Android 6 (arm64).

## Keys and access

All secrets were removed from the repo. Generate your own:

| What | How |
|---|---|
| Node key | `cham-server -genkey -keyfile server.key` |
| Client key | `cham-keygen` (public part goes into the node allowlist) |
| Bulletin-board token | any long random string; set via `CITP_CF_BOARD_TOKEN` on the node and in the worker's `wrangler.toml` |
| `android/app/src/main/assets/ks-vpn.key` | replace with your own installation key |

**Never commit** real keys or `.env` files — they are excluded via `.gitignore`.

## Tests and verification

```bash
go test ./...
go vet ./...
bash scripts/security-check.sh   # catches accidentally committed secrets
```

Independent wire-format parser: `protocol/reference_parser.py`.

## Troubleshooting

- **The node stays silent on connect** — by design: unauthenticated probes get a 0-byte blackhole response. Check the allowlist and keys.
- **`chamd` cannot bring up TUN** — run as Administrator and make sure `wintun.dll` sits next to the exe.
- Node logs: `journalctl -u cham-server -n 100 --no-pager`.

## License

See `LICENSE-NOTICE.md`. Third-party components (Wintun, etc.) are distributed under their own licenses (`tools/wintun/LICENSE.txt`).
