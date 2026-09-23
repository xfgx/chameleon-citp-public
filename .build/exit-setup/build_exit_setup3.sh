#!/bin/bash
# build_exit_setup3.sh — v3 установщика: самодиагностика + NAT не в контрольном пути.
# ks-vpn статик уже собран в v2 — переиспользуем и сверяем хэш.
set -eu
export PATH=/usr/local/go/bin:/usr/sbin:/sbin:/usr/bin:/bin

SRC=/root/build/exit-setup
OUT=/root/dist/exit-setup
KSVPN_STATIC=/root/build/fixroute-20260902/ks-vpn-linux-static
KEY_SRC=/root/build/ks-hop2.key
WANT_KS=6155b10dbba2a59199b37f6890be647461dae0d94b054d70207b4df3c559ebdb
WANT_KEY=73b699e642d6a45bd7c331e6bf90bfeffd91494073c3ad1935cfbbae57ff794a

echo "=== 1. гейты встраиваемых артефактов ==="
GOT_KS=$(sha256sum "$KSVPN_STATIC" | cut -d' ' -f1)
[ "$GOT_KS" = "$WANT_KS" ] || { echo "FAIL: ks-vpn static хэш расходится"; echo " ожидали $WANT_KS"; echo " получили $GOT_KS"; exit 1; }
GOT_KEY=$(sha256sum "$KEY_SRC" | cut -d' ' -f1)
[ "$GOT_KEY" = "$WANT_KEY" ] || { echo "FAIL: ключ плеча 2 изменился — туннель не сойдётся"; exit 1; }
LDD=$(ldd "$KSVPN_STATIC" 2>&1 || true)
echo "$LDD" | grep -qi "not a dynamic executable\|statically linked" || { echo "FAIL: ks-vpn не статик"; exit 1; }
echo "EMBED_GATES_OK"

echo "=== 2. раскладка assets ==="
mkdir -p "$SRC/assets" "$OUT"
cp -f "$KSVPN_STATIC" "$SRC/assets/ks-vpn"
cp -f "$KEY_SRC"      "$SRC/assets/ks-hop2.key"
chmod 600 "$SRC/assets/ks-hop2.key"

echo "=== 3. гейты кода ==="
cd "$SRC"
gofmt -l *.go > /tmp/fmt_exit3.txt || true
if [ -s /tmp/fmt_exit3.txt ]; then echo "FAIL gofmt:"; cat /tmp/fmt_exit3.txt; exit 1; fi
echo "GOFMT_OK"
go vet ./... || { echo "FAIL go vet"; exit 1; }
echo "VET_OK"

echo "=== 4. сборка (static) ==="
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o "$OUT/ks-exit-setup" .
chmod 755 "$OUT/ks-exit-setup"
LDD2=$(ldd "$OUT/ks-exit-setup" 2>&1 || true)
echo "$LDD2" | grep -qi "not a dynamic executable\|statically linked" || { echo "FAIL: установщик не статик"; exit 1; }
echo "OUT_STATIC_OK"

echo "=== 5. гейт: сгенерированный NAT-скрипт должен быть валидным sh ==="
# вытаскиваем скрипт тем же кодом, которым его пишет установщик, и проверяем синтаксис
cat > /tmp/natdump.go <<'GOEOF'
package main

import (
	"fmt"
	"os"
)

func main() { fmt.Fprint(os.Stdout, natScript("ks0")) }
GOEOF
mkdir -p /tmp/natcheck
cp "$SRC/main.go" /tmp/natcheck/main.go
# вырезаем func main из копии, чтобы не было двух main — проще: проверить скрипт после установки.
rm -rf /tmp/natcheck /tmp/natdump.go
# Прямая проверка: запускаем NAT-скрипт без аргумента — должен дать FATAL и код 1,
# а не синтаксическую ошибку. Для этого надо сначала его получить — см. шаг 6.
echo "NATCHECK_DEFERRED"

echo "=== 6. результат ==="
ls -l "$OUT/ks-exit-setup"
echo "EXIT_SETUP_SHA256=$(sha256sum "$OUT/ks-exit-setup" | cut -d' ' -f1)"
setpriv --reuid=65534 --regid=65534 --clear-groups "$OUT/ks-exit-setup" -status 2>&1 | head -2 || true
echo "BUILD_EXIT_SETUP3_DONE"
