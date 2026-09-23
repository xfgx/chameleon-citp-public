# CITP — карта исследования (wire-format, инварианты, обход)

Источники: `protocol/wire-format.md`, `protocol/INVARIANTS.md`, `protocol/overview.md`,
`internal/chameleon/citp_object.go`, `protocol/formal/CITP.tla`.

## Что такое CITP

Chameleon Intent Transport Protocol — мультиплексированный транспорт намерений
поверх carrier-канала. Каскад: клиент -> RU-нода (192.0.2.10) -> Myserv (198.51.100.10:8443).

## Wire-format

5-байтный mux-заголовок = StreamID (4 B BE uint32, 0 = session control) + Command (1 B) + varlen payload.

| Команда | Код | Назначение |
| --- | --- | --- |
| smOpen/OpenOK/OpenErr | 0x01-0x03 | открытие потока |
| smData | 0x04 | данные потока |
| smClose | 0x05 | закрытие |
| smPing/smPong | 0x06-0x07 | keepalive |
| smResolve/ResolveOK/ResolveErr | 0x08-0x0A | DNS-разрешение |
| smOpenAuth | 0x0B | открытие с авторизацией |
| smCITPObject | 0x0C | объект CITP |
| smResume/ResumeOK/ResumeErr | 0x0D-0x0F | возобновление сессии |

CITPObject = 50 B header (ObjectID u64, ParentID u64, StreamID u32, ObjectType u16,
DeliveryMode u8, Flags u8, Offset u64, ExpiryUnixMs i64, MonotonicSeq u64, PayloadLen u16)
+ payload + 32 B AuthTag. DeliveryMode 0x01-0x05.

## Инварианты I1-I10

1. I1 целостность AuthTag.
2. I2 временное истечение (expiry).
3. I3 привязка к сессии/эпохе.
4. I4 монотонная последовательность.
5. I5 привязка DNS-к-соединению.
6. I6 нераскрытие личности при миграции.
7. I7 изоляция секрета потока.
8. I8 упорядоченный поток намерений.
9. I9 завершение после сброса.
10. I10 ограниченная стоимость ресурсов.

CITP.tla проверяет их модельно; не заявлять TLC без записанного прогона.

## Механизмы обхода

| Механизм | Суть |
| --- | --- |
| carrier drbg | детерминированный shaper под профиль трафика |
| phantom TTL | CDT/refraction, фантомные TTL |
| DNS-binding | резолв только через свой канал, TTL 300 s |
| migration | смена адреса без раскрытия личности |
| beacon 53/udp | контроль-канал cham-server |

## Границы (anti-SSRF)

Блокируются: 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16,
169.254.0.0/16, fe80::/10, 100.64.0.0/10. Blackhole 45 s + strike-list.

## Куда смотреть при новой идее

- Границы слоёв intent<->object<->carrier — там живут утечки.
- Инварианты I5/I6: привязка DNS и миграция — самые тонкие.
- Каждый новый wire получает loop-guard в том же изменении.
