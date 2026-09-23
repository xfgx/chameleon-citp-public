# CITP (Chameleon Intent Transport Protocol) — Overview

**Версия спецификации:** 2.1-draft  
**Статус:** Proposed Standard / Experimental Core

---

## 1. Введение

CITP (Chameleon Intent Transport Protocol) — это криптографический протокол транспортного уровня на основе концепции *сетевых намерений* (Intent Transport) и распределённого userspace-сетевого стека (gVisor netstack).

В традиционных VPN (WireGuard, OpenVPN, IPsec) туннелируются «сырые» IP-пакеты (L3). Это приводит к следующим проблемам:
1. Сигнатурный анализ и DPI легко классифицируют туннель по структуре пакетов и ритму обмена.
2. Разрыв физического соединения (смена Wi-Fi ↔ LTE) приводит к разрыву всех активных TCP-сокетов приложений.
3. Отсутствует криптографическая связь между DNS-резолвом и фактическим адресом подключения (риск DNS Rebinding и SSRF).

CITP переносит транспорт на уровень **намерений** (`RESOLVE`, `OPEN`, `RESUME`, `MIGRATE`) и типизированных **объектов** (`CITPObject`), разделяя логический жизненный цикл потока от физического несущего транспорта (*Carrier*).

---

## 2. Архитектура уровней (Layering)

```
+-------------------------------------------------------------+
|                     Applications (Sockets)                  |
+-------------------------------------------------------------+
                              |
+-------------------------------------------------------------+
|             Userspace Netstack & Policy Plane (gVisor)      |
|    - Interception (TUN / SOCKS5)                            |
|    - Declarative Policy Engine (Anti-SSRF / Rate Limits)    |
+-------------------------------------------------------------+
                              |
+-------------------------------------------------------------+
|                      CITP Intent Layer                      |
|    - RESOLVE / OPEN_AUTH / RESUME / MIGRATE                 |
|    - DNS-to-Connection Binding (ResolutionObject)           |
+-------------------------------------------------------------+
                              |
+-------------------------------------------------------------+
|                     CITP Object Engine                      |
|    - Object Model & Causality Graph (ParentID)              |
|    - Semantic Delivery Modes (Reliable, Expiring, Latest)   |
|    - Resumable Streams & Migration Tickets                  |
+-------------------------------------------------------------+
                              |
+-------------------------------------------------------------+
|                    Carrier Abstraction                      |
|    - TCP Carrier / QUIC Carrier / Datagram Carrier          |
|    - Chameleon Profiles (CBR, Jitter, Padding, Cover)       |
+-------------------------------------------------------------+
```

---

## 3. Ключевые свойства

1. **DNS-to-Connection Binding**: Ответы DNS криптографически подписываются узлом (`ResolutionObject`) и проверяются при открытии соединения.
2. **Семантическая доставка**: Поддержка режимов доставки в зависимости от природы данных (`ModeReliableOrdered`, `ModeExpiring`, `ModeLatestOnly`).
3. **Мобильность сессий**: Возобновление логического потока по тикету (`MigrationTicket`) с синхронизацией оффсетов (`SendOffset` / `RecvOffset`).
4. **Устойчивость к зондированию (Blackhole Defense)**: Узел сохраняет полное молчание при некорректных рукопожатиях или зондах.
