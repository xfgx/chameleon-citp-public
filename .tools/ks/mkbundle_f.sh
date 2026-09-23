#!/bin/sh
# mkbundle_f.sh — bundle v11 (20260904f): fail-closed v6-провод + петлестоп v6.
# BAT только ASCII (cmd.exe ломается на UTF-8 в теле .bat), русский текст — в README.txt.
set -e

S=/root/dist/ks-windows-client-20260904e
D=/root/dist/ks-windows-client-20260904f

rm -rf "$D"
mkdir -p "$D/data"
cp "$S/wintun.dll" "$D/"
for f in "$S"/chaossync-selftest*; do [ -e "$f" ] && cp "$f" "$D/"; done
cp "$S/data/ks-vpn.key" "$D/data/"
cp "$S/README.txt" "$D/README.txt"
cp /root/build/ks-vpn-windows-amd64.exe "$D/"

B="$D/run-ks-vpn.bat"
: > "$B"
printf '%s\r\n' '@echo off' >> "$B"
printf '%s\r\n' 'chcp 65001 >nul' >> "$B"
printf '%s\r\n' 'cd /d %~dp0' >> "$B"
printf '%s\r\n' 'echo KS-VPN client v11: TUN 10.99.0.1 -^> node 192.0.2.10' >> "$B"
printf '%s\r\n' 'echo v6 WIRE: random SOURCE addr -^> random DEST in 2001:db8:2::/48, per packet.' >> "$B"
printf '%s\r\n' 'echo FAIL-CLOSED: the v6 wire starts ONLY if this PC has a native global IPv6' >> "$B"
printf '%s\r\n' 'echo   address AND the node pool is proven routed off-tunnel. Otherwise: plain v4 wire.' >> "$B"
printf '%s\r\n' 'echo Read the wire6src: and v6rot: lines in the log. Details: README.txt' >> "$B"
printf '%s\r\n' 'echo.' >> "$B"
printf '%s\r\n' 'ks-vpn-windows-amd64.exe -tunip 10.99.0.1/24 -peerhost 192.0.2.10 -peerport 51820 -listen 23500 -keyfile data\ks-vpn.key -fulltun -v6prefix 2001:db8:1::/48 -v6rot 5 -peerpool6 2001:db8:2::/48 -wire6rot 30 -wire6src auto -wire6srcn 16' >> "$B"
printf '%s\r\n' 'pause' >> "$B"

# честная ASCII-проверка: CR снимаем ПЕРЕД grep (урок: '\r' в классе grep не escape).
if LC_ALL=C tr -d '\015' < "$B" | LC_ALL=C grep -n '[^ -~]'; then
	echo BAT_NOT_ASCII
	exit 1
else
	echo BAT_ASCII_OK
fi

cat >> "$D/README.txt" <<'EOF'

=== v11 (20260904f) ===

Что произошло в полевом прогоне 14:22 (разбор по вашему логу):

1) У этой машины НЕТ нативного глобального IPv6. Дамп wire6src показал
   только маршруты (::/0 через ks0 и ::/0 через Wi-Fi на fe80::1) и НИ ОДНОГО
   глобального адреса. Роутер отдаёт v6-дефолт, но не отдаёт префикс.
   В Wireshark это видно прямо: весь v6-трафик — только link-local fe80::/10.

2) Пул провода НЕ был уведён мимо туннеля (pin вернул exit 3), а туннельный
   ::/0 смотрел в ks0. Итог: датаграммы v6-провода уходили В САМ ТУННЕЛЬ,
   читались обратно из TUN и пересылались снова — петля усиления:
   tunRd 23517 за 3 с (при норме ~110/с), потом 51k -> 184k за 2 с, ~100k пак/с.
   Петлестоп тогда был только v4-вый и этого не видел (loop=0), поэтому и проседал
   сетевой адаптер. Это была ошибка клиента, не провайдера.

Исправлено в v11:

- FAIL-CLOSED: v6-провод включается ТОЛЬКО если (а) найден нативный глобальный
  v6-адрес для источника И (б) пул ноды доказанно уведён мимо туннеля.
  Иначе провод не поднимается ВОВСЕ и клиент честно идёт по v4-проводу.
  Строка в логе начинается с "wire6: FAIL-CLOSED:" и называет причину.

- Петлестоп получил v6-плечо: пакет с адресом назначения внутри пула провода
  в туннель не входит НИКОГДА — даже когда провод выключен (юнит-тест
  TestLoopGuardDrop: оба плеча и оба негативных случая).

- pin при отказе печатает всех кандидатов ::/0 (if / nh / metric), а не только
  "exit status 3" — будет видно, почему не нашёлся нативный шлюз.

Что это значит про случайные адреса (без украшений):

Пока у ПК нет нативного глобального IPv6, случайные ИСХОДНЫЕ v6-адреса
физически невозможны: адрес источника обязан принадлежать интерфейсу.
Варианты:
  1) включить IPv6 у провайдера/роутера — нужен реальный префикс (RA с PIO
     или DHCPv6-PD), а не только v6-дефолт;
  2) поднять 6in4-туннель на самом ПК — тогда у него появится свой /64 и
     рандомизация источника заработает; внешний наблюдатель при этом всё
     равно видит один v4-адрес брокера;
  3) оставить рандомизацию на участке нода <-> выход, где нативный v6 есть.

Перед первым запуском v11 снять хвосты прошлых запусков (PowerShell от админа;
жёсткое завершение без Ctrl+C оставляет маршруты в ActiveStore):

  Remove-NetRoute -DestinationPrefix '2001:db8:2::/48' -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue
  Remove-NetRoute -DestinationPrefix '::/0' -InterfaceAlias 'ks0' -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue

Проверено на этой сборке: gofmt, go vet (linux и windows), go test (включая
TestLoopGuardDrop и TestWireV6SilenceFallback). Живого прогона на Windows у
разработчика нет: Windows-ветка v6 проверяется вашим логом.
EOF

cd "$D"
SUMLIST="ks-vpn-windows-amd64.exe wintun.dll run-ks-vpn.bat README.txt data/ks-vpn.key"
for f in chaossync-selftest*; do [ -e "$f" ] && SUMLIST="$SUMLIST $f"; done
sha256sum $SUMLIST > SHA256SUMS

cd /root/dist
tar czf ks-windows-client-20260904f.tar.gz ks-windows-client-20260904f
ln -sfn ks-windows-client-20260904f.tar.gz ks-windows-client-CURRENT.tar.gz
echo ---ARCHIVE---
sha256sum ks-windows-client-20260904f.tar.gz
stat -c %s ks-windows-client-20260904f.tar.gz
echo ---SUMS---
cat ks-windows-client-20260904f/SHA256SUMS
echo ---CURRENT---
ls -l ks-windows-client-CURRENT.tar.gz
echo ---BAT---
cat -A ks-windows-client-20260904f/run-ks-vpn.bat | head -12
echo BUNDLE_F_DONE
