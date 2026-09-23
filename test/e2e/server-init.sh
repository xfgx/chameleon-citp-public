#!/bin/sh
# Инициализация e2e-ноды: генерирует ключи, готовит allowlist, запускает cham-server.
set -eu
DIR=/run/e2e
mkdir -p "$DIR"
if [ ! -f "$DIR/server.key" ]; then
  cham-keygen -out "$DIR/server.key" >/dev/null 2>&1 || cham-keygen > "$DIR/server.key"
fi
# публичный ключ клиента заранее известен только после генерации клиентской пары —
# для e2e используем тестовый allowlist, который заполняет клиентский init.
: > "$DIR/clients.txt"
touch "$DIR/server.ready"
exec cham-server "$@"
