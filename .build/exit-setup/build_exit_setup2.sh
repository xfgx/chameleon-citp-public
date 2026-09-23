#!/bin/bash
# build_exit_setup2.sh — v2: СНАЧАЛА собираем ks-vpn СТАТИЧЕСКИ (CGO_ENABLED=0),
# ибо установщик поедет на чужой хост с неизвестным libc.
# Динамический бинарь — fail-closed отказ.
set -eu
export PATH=/usr/local/go/bin:/usr/sbin:/sbin:/usr/bin:/bin

REPO=/root/vpn
SRC=/root/build/exit-setup
OUT=/root/dist/exit-setup
KSVPN_STATIC=/root/build/fixroute-20260902/ks-vpn-linux-static
KEY_SRC=/root/build/ks-hop2.key
WIN_REF=4f87ff69d09200b9b4fd8d974fac5a5e54d193a137bbe6a56bc9c194413501ea

echo "=== 0. статическая сборка ks-vpn из того же дерева ==="
cd "$REPO"
# гейт: наши файлы должны быть отформатированы и валидны
gofmt -l cmd/ks-vpn internal/chaossync > /tmp/fmt_ks.txt || true
if [ -s /tmp/fmt_ks.txt ]; then echo "FAIL gofmt:"; cat /tmp/fmt_ks.txt; exit 1; fi
echo "GOFMT_KS_OK"
go vet ./cmd/ks-vpn/... ./internal/chaossync/... || { echo "FAIL vet"; exit 1; }
echo "VET_KS_OK"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o "$KSVPN_STATIC" ./cmd/ks-vpn
chmod 755 "$KSVPN_STATIC"
echo "KSVPN_STATIC_SHA256=$(sha256sum "$KSVPN_STATIC" | cut -d' ' -f1)"
# fail-closed: требуем именно статику
LDD_OUT=$(ldd "$KSVPN_STATIC" 2>&1 || true)
if echo "$LDD_OUT" | grep -qi "not a dynamic executable\|statically linked"; then
	echo "KSVPN_STATIC_OK"
else
	echo "FAIL: ks-vpn не статический:"; echo "$LDD_OUT" | head -5; exit 1
fi
# контроль: Windows-бинарь из этого же дерева должен воспроизводить подтверждённый в поле хэш
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o /tmp/ks-vpn-win-check.exe ./cmd/ks-vpn
WIN_GOT=$(sha256sum /tmp/ks-vpn-win-check.exe | cut -d' ' -f1)
if [ "$WIN_GOT" = "$WIN_REF" ]; then
	echo "WIN_REPRO_OK — дерево то же, что подтверждено в поле"
else
	echo "WARN: Windows-бинарь не воспроизвёлся побайтово"
	echo "  в поле подтверждён: $WIN_REF"
	echo "  сейчас:            $WIN_GOT"
fi
rm -f /tmp/ks-vpn-win-check.exe

echo "=== 1. предполётные проверки установщика ==="
for f in "$KSVPN_STATIC" "$KEY_SRC" "$SRC/main.go" "$SRC/go.mod"; do
	[ -f "$f" ] || { echo "FAIL: нет $f"; exit 1; }
done
echo "FILES_OK"

echo "=== 2. раскладка assets ==="
mkdir -p "$SRC/assets" "$OUT"
cp -f "$KSVPN_STATIC" "$SRC/assets/ks-vpn"
cp -f "$KEY_SRC"      "$SRC/assets/ks-hop2.key"
chmod 600 "$SRC/assets/ks-hop2.key"

echo "=== 3. гейты установщика ==="
cd "$SRC"
gofmt -l *.go > /tmp/fmt_exit.txt || true
if [ -s /tmp/fmt_exit.txt ]; then echo "FAIL gofmt:"; cat /tmp/fmt_exit.txt; exit 1; fi
echo "GOFMT_OK"
go vet ./... || { echo "FAIL go vet"; exit 1; }
echo "VET_OK"

echo "=== 4. сборка установщика (static) ==="
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o "$OUT/ks-exit-setup" .
chmod 755 "$OUT/ks-exit-setup"
LDD2=$(ldd "$OUT/ks-exit-setup" 2>&1 || true)
if echo "$LDD2" | grep -qi "not a dynamic executable\|statically linked"; then
	echo "OUT_STATIC_OK"
else
	echo "FAIL: установщик не статический"; exit 1
fi

echo "=== 5. результат ==="
ls -l "$OUT/ks-exit-setup"
echo "EXIT_SETUP_SHA256=$(sha256sum "$OUT/ks-exit-setup" | cut -d' ' -f1)"
echo "HOP2_KEY_SHA256=$(sha256sum "$KEY_SRC" | cut -d' ' -f1)"

echo "=== 6. санитарные гейты ==="
setpriv --reuid=65534 --regid=65534 --clear-groups "$OUT/ks-exit-setup" -status 2>&1 | head -3 || true
# проверка, что встроенный ks-vpn работоспособен (запускаем саму статику)
"$KSVPN_STATIC" -h 2>&1 | head -4 || true
echo "BUILD_EXIT_SETUP2_DONE"
