#!/bin/bash
# build_exit_setup.sh — собрать самодостаточный установщик зарубежного выхода.
# Собирается НА RU-НОДЕ (там есть Go и ключ второго плеча).
# Модуль НЕ в репозитории: ключ не должен попасть в дерево кода.
set -eu
export PATH=/usr/local/go/bin:/usr/sbin:/sbin:/usr/bin:/bin

SRC=/root/build/exit-setup
OUT=/root/dist/exit-setup
KSVPN_SRC=/root/build/fixroute-20260902/ks-vpn-linux
KEY_SRC=/root/build/ks-hop2.key

echo "=== предполётные проверки ==="
for f in "$KSVPN_SRC" "$KEY_SRC" "$SRC/main.go" "$SRC/go.mod"; do
	[ -f "$f" ] || { echo "FAIL: нет $f"; exit 1; }
done
# бинарь должен быть именно исправленной сборки (фикс маршрутизации)
WANT_KS=b3d42837081ca679dc87e5491b2a257f045d98b65676e31359b76f5a1686b093
GOT_KS=$(sha256sum "$KSVPN_SRC" | cut -d' ' -f1)
if [ "$GOT_KS" != "$WANT_KS" ]; then
	echo "FAIL: ks-vpn-linux хэш не совпал"; echo "  ожидали $WANT_KS"; echo "  получили $GOT_KS"; exit 1
fi
echo "KSVPN_HASH_OK $GOT_KS"
# бинарь должен быть статическим — иначе на чужом хосте может не запуститься
if command -v file >/dev/null 2>&1; then file "$KSVPN_SRC"; fi
if ldd "$KSVPN_SRC" 2>&1 | grep -qi "not a dynamic\|statically"; then
	echo "STATIC_OK"
else
	echo "WARN: ks-vpn-linux похоже динамический:"; ldd "$KSVPN_SRC" 2>&1 | head -5
fi

echo "=== раскладка assets ==="
mkdir -p "$SRC/assets" "$OUT"
cp -f "$KSVPN_SRC" "$SRC/assets/ks-vpn"
cp -f "$KEY_SRC"   "$SRC/assets/ks-hop2.key"
chmod 600 "$SRC/assets/ks-hop2.key"

echo "=== гейты ==="
cd "$SRC"
gofmt -l . | grep -v '^assets/' > /tmp/fmt_exit.txt || true
if [ -s /tmp/fmt_exit.txt ]; then echo "FAIL gofmt:"; cat /tmp/fmt_exit.txt; exit 1; fi
echo "GOFMT_OK"
go vet ./... || { echo "FAIL go vet"; exit 1; }
echo "VET_OK"

echo "=== сборка (static, linux/amd64) ==="
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o "$OUT/ks-exit-setup" .
chmod 755 "$OUT/ks-exit-setup"
echo "BUILD_OK"

echo "=== результат ==="
ls -l "$OUT/ks-exit-setup"
echo "EXIT_SETUP_SHA256=$(sha256sum "$OUT/ks-exit-setup" | cut -d' ' -f1)"
echo "HOP2_KEY_SHA256=$(sha256sum "$KEY_SRC" | cut -d' ' -f1)"
if ldd "$OUT/ks-exit-setup" 2>&1 | grep -qi "not a dynamic\|statically"; then echo "OUT_STATIC_OK"; fi

echo "=== санитарная проверка: -h не требует root и не ломается ==="
"$OUT/ks-exit-setup" -h 2>&1 | head -20 || true
echo "=== проверка гейта root (запуск от nobody должен быть отвергнут) ==="
setpriv --reuid=65534 --regid=65534 --clear-groups "$OUT/ks-exit-setup" -status 2>&1 | head -3 || true
echo "BUILD_EXIT_SETUP_DONE"
