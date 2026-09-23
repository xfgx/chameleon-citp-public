# Contributing / Участие в разработке

## English

Thanks for your interest in improving Chameleon CITP!

### Build

```bash
git clone <repo-url> && cd chameleon-citp-public
go mod download
make build        # or: go build ./...
```

Requirements: **Go ≥ 1.26** (see `go.mod`). Windows client additionally needs
`wintun.dll` from `tools/wintun/`.

### Test

```bash
make test         # go test -race ./...
make vet          # go vet ./...
make security     # gitleaks + govulncheck
make e2e          # docker compose end-to-end (server + CLI client)
```

All checks must pass before submitting a PR. CI runs the same steps on
Linux, Windows and macOS.

### Code style

- Standard `gofmt` formatting; CI enforces `golangci-lint`.
- Comments in Russian or English are both fine — match the surrounding file.
- Keep protocol changes compatible with `protocol/` specs; update the spec
  and `protocol/reference_parser.py` in the same PR.

### Committing

- Never commit secrets, keys, `.env` files or real server addresses —
  `make security` (gitleaks) will fail. See `.gitignore`.
- Small, focused PRs are easier to review.

---

## Русский

Спасибо за интерес к развитию Chameleon CITP!

### Сборка

```bash
git clone <url-репозитория> && cd chameleon-citp-public
go mod download
make build        # или: go build ./...
```

Требования: **Go ≥ 1.26** (см. `go.mod`). Windows-клиенту дополнительно нужен
`wintun.dll` из `tools/wintun/`.

### Тестирование

```bash
make test         # go test -race ./...
make vet          # go vet ./...
make security     # gitleaks + govulncheck
make e2e          # сквозной тест в docker compose (сервер + CLI-клиент)
```

Все проверки должны быть зелёными перед PR. CI прогоняет то же самое на
Linux, Windows и macOS.

### Стиль кода

- Стандартное форматирование `gofmt`; в CI работает `golangci-lint`.
- Комментарии на русском или английском — как в окружающем файле.
- Изменения протокола должны совпадать со спецификациями в `protocol/`;
  обновляйте спецификацию и `protocol/reference_parser.py` в том же PR.

### Коммиты

- Никогда не коммитьте секреты, ключи, `.env` и реальные адреса серверов —
  `make security` (gitleaks) упадёт. См. `.gitignore`.
- Небольшие сфокусированные PR ревьюить проще.
