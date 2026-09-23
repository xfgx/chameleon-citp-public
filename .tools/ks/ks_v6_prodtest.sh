#!/bin/bash
# ks_v6_prodtest.sh — живой сквозной тест v6-ротации против prod-цепочки:
# netns-клиент на RU -> prod ks-vpn-node (:51820) -> ks1 -> Myserv -> 6in4 ->
# интернет и обратно. Клиент переживает сессию (nohup), счётчики до/после.
set -u
export PATH=/usr/sbin:/sbin:/usr/bin:/bin
KS=/root/build/ks-vpn
POOL=2001:db8:1::/48
LOG=/tmp/ksv6prod2.log

# чистый старт клиента в T1
pkill -f 'ks-vpn .*-tun kst' 2>/dev/null; sleep 0.5
ip netns del T1 2>/dev/null; ip link del th1 2>/dev/null
ip netns add T1
ip link add th1 type veth peer name tp1
ip link set tp1 netns T1
ip addr add 10.0.77.254/24 dev th1; ip link set th1 up
ip netns exec T1 ip addr add 10.0.77.1/24 dev tp1
ip netns exec T1 ip link set tp1 up; ip netns exec T1 ip link set lo up

ip netns exec T1 nohup $KS -keyfile /root/build/ks-vpn.key -tun kst \
  -tunip 10.99.0.3/24 -peerhost 10.0.77.254 -peerport 51820 -listen 24510 \
  -outdir c2n -indir n2c -T 8 -tunv6 -v6prefix $POOL -v6rot 3 >$LOG 2>&1 &
sleep 2
ip netns exec T1 ip -6 route replace default dev kst
echo "pool-адресов на kst: $(ip netns exec T1 ip -6 addr show dev kst | grep -c 'inet6 2a03')"

echo '--- ДО: нода / exit ---'
journalctl -u ks-vpn-node --no-pager -n 2 | grep -o 'стадии.*' | tail -1
journalctl -u ks-vpn-exit --no-pager -n 2 | grep -o 'стадии.*' | tail -1

echo '--- 6 ping6 google (ровесники ротаций) ---'
for i in 1 2 3 4 5 6; do
  ip netns exec T1 ping -6 -c 1 -W 2 2001:4860:4860::8888 2>&1 | grep -E 'bytes from|packet loss'
  sleep 0.5
done

echo '--- клиентские стадии ---'
grep стадии $LOG | tail -2
echo '--- ПОСЛЕ: нода / exit ---'
journalctl -u ks-vpn-node --no-pager -n 2 | grep -o 'стадии.*' | tail -1
journalctl -u ks-vpn-exit --no-pager -n 2 | grep -o 'стадии.*' | tail -1
echo PRODTEST2_DONE
