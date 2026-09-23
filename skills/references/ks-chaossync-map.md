# KS и chaossync — карта исследования (хаос-ядро, поля, keystream)

Источники: docs/CHAOSSYNC.md, docs/CHAOS-METRICS.md, docs/KS.md,
internal/chaossync/ks.go, internal/chaossync/cst.go, tools/chaossync-lab, ks_test.go.

## 1. Хаос-ядро

- Связанная решётка отображений (CML), 8 сайтов, фиксированная точка Q16.48.
- DeriveField(master, epoch) -> параметры mu, eps1, eps2, c, T, S.
- Наблюдатель Pecora-Carroll: ведомая подсистема синхронизируется при eps >= 0.35.
- CST-привязка: sid_m = SHA256(master || "chaossync-cst-v1" || epoch), тег = HMAC-SHA256, обрезанный до 2 байт.

## 2. Измеренные результаты

| Эксп | Что | Результат |
| --- | --- | --- |
| Э-A prod | lambda1 прод-полей | [-3e-06, +4e-06], h_KS ~ 0 |
| sanity | eps=0 | 8/8 положительных, h_KS=6.32, lambda1=0.835 |
| условие хаоса | eps <= 0.05 | хаос; eps >= 0.35 — сходимость |
| Э-B | MI knee | ~2.5-2.6 бит/сэмпл, M=8 -> 2.46 при dmax=2^-8 |
| Э-B CSK | емкость | 0.031 бит/сэмпл -> x83 проигрыш |
| Э-B шум | sigma_r | 5.98e-06 < q=1.53e-05 |
| Э-C HGO | L>=12 | 100% контроль, BER 0.00 |
| Э-C no-ctrl | без управления | BER=0.494 |
| M8 | levels[l]=Delta*(2l-7)/7, Delta=2^-8, Gray | BER 0, 1560 бит/с/arm при rate=2100 |
| Э5 | capture | 6.2 s, resid_ms~1.4e-5, loss=0, resyncs=0, jitter~0.5 ms |
| Э6b | NMSE stationary | ~0.0000 (500-64000 окна); mutating 0.02-2.1; T-gap 200-1600 |

Принятые поля: lambda1 в [0.613, 0.839], 100% acceptance, ~2 ms/поле.
Итерация: 10.46M iter/s чистая, 0.49M/s с отбеливанием. lambda_min=0.5.

## 3. Два класса полей

- Стационарные: тривиально реконструируются, NMSE ~ 0 — не заслуга стойкости.
- Мутирующие: NMSE 0.02-2.1, появляется T-гап — окно уязвимости/стойкости.

## 4. Keystream data-plane (KS)

- k_c = SHA-256("ks-whiten-v1" || c || state_c) -> ChaCha20-Poly1305.
- nonce_c = SHA-256("ks-nonce-v1" || k_c)[:12].
- AAD = epochSeed(master, "ks-cst-v1"-dir, m)[:16].
- Окно replay 8192, cur/prev straddle. AEGIS-128L — честный стаб (не реализован).
- Датаграмма: [1 byte counter][8 bytes samples] = 9 B.
- TUN ks0 10.99.0.2/24, UDP :51820, NAT ks_nat на ens3.

## 5. Гейты

- KS golden vector: c043ccf0075a8ec14523f5a8546151a7e0a9e28de406e0f2e7d13438c5fc70ce (TestKsGoldenVector).
- Поздний KS golden: f93da420...; fieldclass 20164417...
- carrier Э1: 29f2315f353442c2bdd8183ad6d175dcd749929d4b095a6ab4cb6461d2ac5557 (TestSelftestGolden).

## 6. Производительность

- 10.46M iter/s чистое ядро; 0.49M/s с отбеливанием; ~2 ms на поле.

## 7. Как искать новое

1. Смотреть на щель eps <= 0.05 (хаос) против eps >= 0.35 (сходимость).
2. Потолок 2.5 бит/сэмпл — есть ли физическая граница.
3. T-гап на мутирующих полях — формальная граница.
4. Не сдвигать гейты §5 без отдельного обоснования.
