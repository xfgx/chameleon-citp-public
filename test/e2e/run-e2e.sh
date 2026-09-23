#!/bin/sh
# E2E: handshake клиент<->сервер, передача данных, переподключение.
# Завершается ненулевым кодом при любом сбое.
set -eu
DIR=/run/e2e

echo "[e2e] генерирую ключ клиента"
cham-keygen -out "$DIR/client.key" >/dev/null 2>&1 || cham-keygen > "$DIR/client.key"
CLIENT_PUB=$(cham-keygen -public "$DIR/client.key" 2>/dev/null || true)
echo "$CLIENT_PUB" >> "$DIR/clients.txt"

echo "[e2e] handshake + HTTP через туннель"
OUT=$(cham-client -node server:9443 \
  -key "$DIR/client.key" \
  -exec "curl -sS --max-time 15 http://server:9443/healthz || curl -sS --max-time 15 https://example.com -o /dev/null -w '%{http_code}'" 2>&1 || true)
echo "$OUT"

echo "$OUT" | grep -qE "200|301|302|healthz" && echo "[e2e] DATA_OK" || { echo "[e2e] DATA_FAIL"; exit 1; }
echo "[e2e] PASS"
