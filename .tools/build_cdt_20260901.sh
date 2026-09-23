#!/bin/bash
# build_cdt_20260901.sh — полная сборка CDT/chaossync артефактов на RU-ноде.
set -u
cd /root/vpn || exit 1
G=/usr/local/go/bin/go
OUT=/root/dist/cdt-chaos-20260901
mkdir -p "$OUT"
FAIL=0

build_one() {
  local c="$1"
  CGO_ENABLED=0 "$G" build -trimpath -ldflags '-s -w' -o "$OUT/$c-linux-amd64" "./cmd/$c" || { echo "FAIL linux $c"; FAIL=1; }
}
build_win() {
  local c="$1"
  CGO_ENABLED=0 GOOS=windows GOARCH=amd64 "$G" build -trimpath -ldflags '-s -w' -o "$OUT/$c-windows-amd64.exe" "./cmd/$c" || { echo "FAIL windows $c"; FAIL=1; }
}

for c in chaossync-server chaossync-client chaossync-selftest cdt-server cdt-client cdt-socks cdt-probe; do
  build_one "$c"
  build_win "$c"
done
# TUN-мосты — linux-only (TUN через /dev/net/tun; Wintun-порт — следующий этап)
for c in cdt-tun cdt-vpn; do
  build_one "$c"
done

cd "$OUT" && sha256sum * > SHA256SUMS && ls -la
echo "BUILD_FAIL=$FAIL"
echo BUILD_SCRIPT_DONE
