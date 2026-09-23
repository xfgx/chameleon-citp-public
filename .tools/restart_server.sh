#!/bin/bash
# Перезапуск chaossync-server на порту 4500 для cross-border теста Э5.
cd /root/build || exit 9

# Убить старый пробник и старый сервер по pidfile / точному имени бинаря.
[ -f probe.pid ] && kill "$(cat probe.pid)" 2>/dev/null
pkill -x udp_probe.py 2>/dev/null
pkill -f 'build/udp_probe' 2>/dev/null
pkill -x chaossync-serve 2>/dev/null
sleep 1

# Проверить, свободен ли порт 4500.
if ss -lun 2>/dev/null | grep -q ':4500 '; then
  echo "PORT_4500_BUSY"
fi

rm -f cb-server.log cb-server.pid
nohup ./chaossync-server -keyfile cb.key -listen 0.0.0.0:4500 -metrics 127.0.0.1:19090 -T 8 -c 0.85 -rate 1000 -S 32 -batch 4 > cb-server.log 2>&1 &
echo $! > cb-server.pid
disown
sleep 1
echo '=== server.log ==='
head -5 cb-server.log
echo '=== порт 4500 ==='
ss -lunp 2>/dev/null | grep 4500 || echo '(не слушает)'
echo '=== pid ==='
cat cb-server.pid
