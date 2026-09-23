#!/bin/bash
# ks_v6wire_test.sh — netns-стенд v6-ПРОВОДА KS (клиент -> случайные адреса
# пула ноды). WA (клиент) --veth dual-stack--> WB (нода, anyip-пул на lo).
# Гейты: (1) inner-трафик ходит по v6-проводу; (2) датаграммы улетают на
# РАЗНЫЕ адреса пула; (3) ответы приходят С ТОГО ЖЕ адреса (pktinfo);
# (4) исходный порт клиента случаен и пересаживается (-wire6rot);
# (5) при обрыве v6-маршрута — откат на v4-провод, туннель не рвётся.
set -u
export PATH=/usr/local/go/bin:/usr/sbin:/sbin:/usr/bin:/bin
KS=/root/build/wirev6-20260904/ks-vpn-linux
POOL=fd6c:2a03:5b4a::/48   # ULA-аналог routed /48 ноды
LOGD=/tmp/ksv6wire; mkdir -p $LOGD

pkill -x ks-vpn-linux 2>/dev/null; sleep 0.3
for n in WA WB; do ip netns del $n 2>/dev/null; done
ip netns add WA; ip netns add WB
ip link add vp1 type veth peer name vp2
ip link set vp1 netns WA; ip link set vp2 netns WB
ip netns exec WA ip addr add 10.0.9.1/24 dev vp1
ip netns exec WA ip -6 addr add 2001:db8:9::1/64 dev vp1
ip netns exec WA ip link set vp1 up; ip netns exec WA ip link set lo up
ip netns exec WB ip addr add 10.0.9.254/24 dev vp2
ip netns exec WB ip -6 addr add 2001:db8:9::254/64 dev vp2
ip netns exec WB ip link set vp2 up; ip netns exec WB ip link set lo up

# нода WB: весь пул локален (anyip), слушает 24509 dual-stack
ip netns exec WB ip -6 route replace local $POOL dev lo
ip netns exec WB $KS -keyfile /root/build/ks-vpn.key -tun ks9 -tunip 10.99.0.2/24 \
  -listen 24509 -peerport 24510 -outdir n2c -indir c2n -T 8 > $LOGD/B.log 2>&1 &
sleep 1
echo "нода: route get случайного адреса пула -> $(ip netns exec WB ip -6 route get fd6c:2a03:5b4a:abcd::123 | head -1)"

# клиент WA: v6-провод в пул (маршрут в пул — через veth, эмуляция нативного v6)
ip netns exec WA ip -6 route replace $POOL via 2001:db8:9::254 dev vp1
ip netns exec WA $KS -keyfile /root/build/ks-vpn.key -tun ks8 -tunip 10.99.0.1/24 \
  -peerhost 10.0.9.254 -peerport 24509 -listen 24510 -outdir c2n -indir n2c -T 8 \
  -peerpool6 $POOL -wire6rot 3 > $LOGD/A.log 2>&1 &
sleep 2
ip netns exec WA ip route replace default dev ks8

echo '=== inner-трафик по v6-проводу (ping 10.99.0.2) ==='
ip netns exec WA ping -c 4 -W 2 10.99.0.2 2>&1 | tail -2

echo '=== захват провода на стороне ноды: цели датаграмм ==='
( ip netns exec WA sh -c 'for i in $(seq 1 12); do ping -c 1 -W 1 10.99.0.2 >/dev/null 2>&1; sleep 0.6; done' & )
sleep 0.5
ip netns exec WB timeout 9 tcpdump -i vp2 -nn 'ip6 and udp and port 24509' -c 14 2>/dev/null | awk '{print $5}' | sed 's/\.24509.*//' | sort -u | head -14

echo '=== ответы ноды (src = hit-адрес, порт 24509) ==='
( ip netns exec WA sh -c 'for i in 1 2 3 4 5 6; do ping -c 1 -W 1 10.99.0.2 >/dev/null 2>&1; sleep 0.5; done' & )
sleep 0.5
ip netns exec WA timeout 6 tcpdump -i vp1 -nn 'ip6 and udp and src port 24509' -c 6 2>/dev/null | awk '{print $3}' | sed 's/\.24509.*//' | sort -u

echo '=== клиент: лог провода (порты/откат) ==='
grep -E 'wire6|стадии' $LOGD/A.log | tail -6

echo '=== откат на v4: рвём v6-маршрут пула ==='
ip netns exec WA ip -6 route del $POOL
sleep 1
ip netns exec WA ping -c 6 -i 0.4 -W 1 10.99.0.2 2>&1 | tail -2
grep -E 'wire6' $LOGD/A.log | tail -3
echo '=== восстановление: после отката v4 обязан работать ==='
sleep 2
ip netns exec WA ping -c 3 -W 2 10.99.0.2 2>&1 | tail -2

pkill -x ks-vpn-linux 2>/dev/null
for n in WA WB; do ip netns del $n 2>/dev/null; done
echo KS_V6WIRE_TEST_DONE
