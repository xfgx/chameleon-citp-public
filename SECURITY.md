# Security Policy / Политика безопасности

## English

**Status: this project has NOT undergone an independent security audit. Do not use it in production to protect against real threats.**

### Reporting a vulnerability

Please report security issues privately via GitHub: open a draft security advisory
(Repository → Security → Advisories → "Report a vulnerability") or contact the maintainers
listed in the repository profile. Do NOT open public issues for security problems.

Please include: affected component/version, reproduction steps, potential impact.
We aim to acknowledge reports within 7 days.

### Scope and limitations

- The protocol and implementation are research-grade; no formal verification has been done.
- Known limitations are documented in `THREAT_MODEL.md` and `docs/`.
- Cryptographic code is custom and has not been reviewed by third parties.

### Supported versions

Only the latest `main` branch and the most recent release tag receive fixes.

---

## Русский

**Статус: проект НЕ проходил независимый аудит безопасности. Не используйте его в production для защиты от реальных угроз.**

### Как сообщить об уязвимости

Сообщайте о проблемах приватно через GitHub: черновик security advisory
(Repository → Security → Advisories → «Report a vulnerability») или напрямую
мейнтейнерам из профиля репозитория. НЕ открывайте публичные issues по безопасности.

Укажите: затронутый компонент/версию, шаги воспроизведения, потенциальное влияние.
Мы стараемся подтверждать получение в течение 7 дней.

### Ограничения

- Протокол и реализация — исследовательского уровня; формальной верификации не было.
- Известные ограничения описаны в `THREAT_MODEL.md` и `docs/`.
- Криптографический код собственный и не проверялся сторонними аудиторами.

### Поддерживаемые версии

Исправления выходят только для ветки `main` и последнего релизного тега.
