#!/bin/bash
# ks_v6src_test.sh — netns-стенд ПОЛНОЙ рандомизации v6-ПРОВОДА:
# СЛУЧАЙНЫЙ ИСХОДНЫЙ адрес клиента -> СЛУЧАЙНЫЙ адрес пула ноды,
# каждая датаграмма (ТЗ владельца 2026-09-04).
#
# WA (клиент, свой /64 для источников) --veth dual-stack--> WB (нода, anyip-пул).
# Гейты:
#  (1) inner-трафик жив через v6-провод;
#  (2) ИСХОДНЫЕ адреса датаграмм — РАЗНЫЕ и все из префикса клиента;
#  (3) ЦЕЛИ — РАЗНЫЕ и все из пула ноды;
#  (4) ответы доходят обратно (именно этого не было в поле 4 сентября);
#  (5) при обрыве v6 — откат на v4, туннель не рвётся.
set -u
export PATH=/usr/local/go/bin:/usr/sbin:/sbin:/usr/bin:/bin
KS=${KS:-/root/build/wiresrc6-20260904/ks-vpn-linux}
POOL=fd6c:2a03:5b4a::/48    # ULA-аналог routed /48 ноды (назначение)
SRC=fd6c:2a03:5b49:1::/64   # «нативный» /64 клиента (источники)
LOGD=/tmp/ksv6src; mkdir -p $LOGD

pkill -x ks-vpn-linux 2>/dev/null; sleep 0.3
for n in SA SB; do ip netns del $n 2>/dev/null; done
ip netns add SA; ip netns add SB
ip link add sp1 type veth peer name sp2
ip link set sp1 netns SA; ip link set sp2 netns SB
ip netns exec SA ip addr add 10.0.8.1/24 dev sp1
ip netns exec SA ip -6 addr add 2001:db8:8::1/64 dev sp1
ip netns exec SA ip link set sp1 up; ip netns exec SA ip link set lo up
ip netns exec SB ip addr add 10.0.8.254/24 dev sp2
ip netns exec SB ip -6 addr add 2001:db8:8::254/64 dev sp2
ip netns exec SB ip link set sp2 up; ip netns exec SB ip link set lo up

# нода SB: весь пул назначения локален (anyip, как на RU), и он знает
# обратный маршрут в префикс источников клиента.
ip netns exec SB ip -6 route replace local $POOL dev lo
ip netns exec SB ip -6 route replace $SRC via 2001:db8:8::1 dev sp2
ip netns exec SB $KS -keyfile /root/build/ks-vpn.key -tun ks7 -tunip 10.99.0.2/24 \
  -listen 24609 -peerport 24610 -outdir n2c -indir c2n -T 8 > $LOGD/B.log 2>&1 &
sleep 1

# клиент SA: префикс источников локален (эмуляция своего /64 от провайдера),
# маршрут в пул ноды — через veth.
ip netns exec SA ip -6 route replace local $SRC dev lo
ip netns exec SA ip -6 route replace $POOL via 2001:db8:8::254 dev sp1
ip netns exec SA $KS -keyfile /root/build/ks-vpn.key -tun ks6 -tunip 10.99.0.1/24 \
  -peerhost 10.0.8.254 -peerport 24609 -listen 24610 -outdir c2n -indir n2c -T 8 \
  -peerpool6 $POOL -wire6rot 3 -wire6src $SRC -wire6srcn 8 > $LOGD/A.log 2>&1 &
sleep 2

echo '=== (0) клиент поднял пул источников ==='
grep -E 'wire6src|wire6:' $LOGD/A.log | head -6

echo '=== (1) inner-трафик по v6-проводу (ping 10.99.0.2) ==='
ip netns exec SA ping -c 4 -W 2 10.99.0.2 2>&1 | tail -2

echo '=== (2+3) захват на ноде: ИСТОЧНИК -> ЦЕЛЬ каждой датаграммы ==='
( ip netns exec SA sh -c 'for i in $(seq 1 24); do ping -c 1 -W 1 10.99.0.2 >/dev/null 2>&1; sleep 0.25; done' & )
sleep 0.5
ip netns exec SB timeout 10 tcpdump -i sp2 -nn "ip6 and udp and dst port 24609" -c 30 2>/dev/null \
  | awk '{s=$3; d=$5; sub(/:$/,"",d); sub(/\.[0-9]+$/,"",s); sub(/\.[0-9]+$/,"",d); print s" -> "d}' > $LOGD/cap.txt
echo "-- всего захвачено: $(wc -l < $LOGD/cap.txt)"
echo "-- уникальных ИСТОЧНИКОВ (адрес, без порта): $(sed -E 's/ ->.*//' $LOGD/cap.txt | sort -u | wc -l)"
sed -E 's/ ->.*//' $LOGD/cap.txt | sort -u | head -10
echo "-- уникальных ЦЕЛЕЙ: $(sed -E 's/.*-> //' $LOGD/cap.txt | sort -u | wc -l)"
sed -E 's/.*-> //' $LOGD/cap.txt | sort -u | head -10
echo "-- источники ВНЕ префикса клиента (обязано быть 0): $(sed -E 's/ ->.*//' $LOGD/cap.txt | grep -v '^$' | grep -cv '^fd6c:2a03:5b49:1:')"
echo "-- цели ВНЕ пула ноды (обязано быть 0): $(sed -E 's/.*-> //' $LOGD/cap.txt | grep -v '^$' | grep -cv '^fd6c:2a03:5b4a:')"

echo '=== (4) ответы ноды доходят до клиента (src=hit-адрес пула) ==='
( ip netns exec SA sh -c 'for i in $(seq 1 10); do ping -c 1 -W 1 10.99.0.2 >/dev/null 2>&1; sleep 0.4; done' & )
sleep 0.5
ip netns exec SA timeout 7 tcpdump -i sp1 -nn "ip6 and udp and src port 24609" -c 8 2>/dev/null \
  | awk '{s=$3; d=$5; sub(/:$/,"",d); sub(/\.[0-9]+$/,"",s); sub(/\.[0-9]+$/,"",d); print s" -> "d}' | sort -u | head -8

echo '=== счётчики клиента (udpRecv/tunWr ОБЯЗАНЫ расти) ==='
grep 'стадии' $LOGD/A.log | tail -3

echo '=== (5) откат на v4: рвём v6-маршрут пула ==='
ip netns exec SA ip -6 route del $POOL
sleep 1
ip netns exec SA ping -c 6 -i 0.4 -W 1 10.99.0.2 2>&1 | tail -2
grep -E 'wire6' $LOGD/A.log | tail -3

echo '=== восстановление: после отката v4 обязан работать ==='
sleep 2
ip netns exec SA ping -c 3 -W 2 10.99.0.2 2>&1 | tail -2

pkill -x ks-vpn-linux 2>/dev/null
for n in SA SB; do ip netns del $n 2>/dev/null; done
echo KS_V6SRC_TEST_DONE
