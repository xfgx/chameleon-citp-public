# CITP v3.0: CPI-Scatter / ZPL4 и Sub-Horizon TTL Smuggling

Два экспериментальных транспорта Chameleon, интегрированные в
`internal/chameleon` как библиотечные примитивы + CLI-инструменты.

## 1. CPI-Scatter + ZPL4 (`phantom.go`, CLI `tools/citp-sim`)

- **CPI-Scatter** — каждый пакет направляется к случайному публичному IPv4
  (`GenerateRandomIP`, LCG Numerical Recipes с отбраковкой зарезервированных
  диапазонов RFC 6890 без смещения распределения). Статический IP-бан
  неприменим: единого server IP нет.
- **ZPL4** — 12 байт данных в полях TCP `Seq/Ack/TSval` при нулевом
  L7 payload:

```
Seq    = chunk[0:4]  XOR mask[0:4]
Ack    = chunk[4:8]  XOR mask[4:8]
TSval  = chunk[8:12] XOR mask[8:12]
mask   = HMAC-SHA256(hmacKey, "zpl4-mask"  || seqNum)
IPv4ID = HMAC-SHA256(hmacKey, "zpl4-check" || seqNum || chunk)[12:14]
hmacKey = HMAC-SHA256(secret, "CITP-v3-Phantom-Entanglement-Key")
```

Приёмник знает `seqNum` (синхронный счётчик), восстанавливает `chunk` XOR-ом
и проверяет подлинность через `IPv4ID` за O(1).

**Отличие от эталонного прототипа:** прототип `DecodeZPL4` читал поле
`HeaderData`, которого у реального приёмника нет, — схема была замкнута сама на
себя (тег считался от неизвестного приёмнику чанка). Здесь декодирование
честное: данные восстанавливаются только из проводных полей.

**Граница симуляции:** `citp-sim` валидирует криптографический слой (roundtrip,
целостность, энтропия заголовков ≥ 7.9 бит/байт). Отправка сырых
TCP-заголовков на провод (AF_PACKET/eBPF) — инфраструктурный слой, как у
refraction carrier, и сознательно не реализована.

## 2. Sub-Horizon TTL Smuggling (`ttlsmuggle.go`, CLI `tools/ttl-smuggle`)

Клиент шлёт кадры к decoy-адресу с TTL, которого хватает ровно до TAP-узла:
дальше маршрутизатор уничтожает пакет (TTL Expired), decoy не видит ничего.

Кадр (UDP payload):

```
[4B magic "TTLS"] [8B seq] [12B nonce] [AES-256-GCM ciphertext || 16B tag]
AAD = magic || seq || nonce
ключ = HKDF-SHA256(PSK, info="chameleon-ttl-smuggle")
```

Режимы: `-mode send|recv|selftest`. `selftest` — сквозная проверка на loopback.

**Ограничение (как у refraction):** нужен сопряжённый on-path TAP-узел.

## Тесты и сборка

```bash
go test -run 'ZPL4|Phantom|Shannon|RandomIP|TTLS' -v ./internal/chameleon
go test ./internal/chameleon            # полный прогон
go run ./tools/ttl-smuggle -mode selftest -count 5
./scripts/build-release.sh              # полный релиз (Go 1.26.3)
```

Бинарники релиза: `citp-sim-{linux,windows}-amd64`,
`ttl-smuggle-{linux,windows}-amd64` (+ запись в `dist/release/SHA256SUMS`).
CI: `.github/workflows/citp-v3.yml` прогоняет тесты, selftest и собирает
бинарники артефактом на каждый push по затронутым путям.

## 3. Клиент↔нода: TTLS-фронт (подключение самого клиента)

cham-server:

    -ttls-listen 0.0.0.0:55353   UDP-приёмник фантомных кадров (пустой = выкл)
    -ttls-secret <PSK>           общий с клиентами секрет (пустой = из ключа ноды)

cham-client:

    -carrier ttls -connect <нода>:55353 -ttls-secret <PSK> [-ttls-ttl 64]

Клиент шлёт один зашифрованный UDP-кадр (AES-256-GCM, ключ HKDF из PSK) с
фиксированным IP TTL на TTLS-фронт ноды; нода расшифровывает, логирует и
отвечает эхом тем же каналом. TCP-соединение не создаётся. Проверено через
интернет: внешний клиент ↔ ru-node-1 и ↔ myserv (см. citp-v3-build2.log).
