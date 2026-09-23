#!/bin/bash
# ks_v6_test.sh — netns-прогон v6-транзита KS с ротацией адресов пула.
# Топология: KA (клиент, ротация ULA /48) --KS--> KB (нода, -tunv6, форвардинг)
# --v6--> KC («интернет», UDPv6-слушатель печатает источники).
# Гейты: (1) v6 проходит сквозь KS; (2) источники у KC ротируются (>=3 разных
# за прогон при -v6rot 2); (3) все источники из пула; (4) v4 ping жив;
# (5) без -tunv6 disable_ipv6=1 (дефолт сохранён).
set -u
export PATH=/usr/local/go/bin:/usr/sbin:/sbin:/usr/bin:/bin
B=/root/build/v6rot-20260904
KS=$B/ks-vpn-linux
POOL=fd6b:6b73:5b49::/48
C_ADDR=2001:db8:666::2
LOGD=/tmp/ksv6; mkdir -p $LOGD

pkill -x ks-vpn-linux 2>/dev/null; sleep 0.3
for n in KA KB KC; do ip netns del $n 2>/dev/null; done
ip netns add KA; ip netns add KB; ip netns add KC

ip link add va type veth peer name vb
ip link set va netns KA; ip link set vb netns KB
ip netns exec KA ip addr add 10.0.9.1/24 dev va
ip netns exec KA ip link set va up; ip netns exec KA ip link set lo up
ip netns exec KB ip addr add 10.0.9.254/24 dev vb
ip netns exec KB ip link set vb up; ip netns exec KB ip link set lo up

ip link add vc1 type veth peer name vc2
ip link set vc1 netns KB; ip link set vc2 netns KC
ip netns exec KB ip -6 addr add 2001:db8:666::1/64 dev vc1
ip netns exec KB ip link set vc1 up
ip netns exec KC ip -6 addr add $C_ADDR/64 dev vc2
ip netns exec KC ip link set vc2 up; ip netns exec KC ip link set lo up
ip netns exec KC ip -6 route add $POOL via 2001:db8:666::1

# нода B
ip netns exec KB $KS -keyfile /root/build/ks-vpn.key -tun ks9 -tunip 10.99.0.2/24 \
  -listen 24509 -peerport 24510 -outdir n2c -indir c2n -T 8 -tunv6 > $LOGD/B.log 2>&1 &
sleep 1
ip netns exec KB sysctl -qw net.ipv6.conf.all.forwarding=1
ip netns exec KB ip -6 route replace $POOL dev ks9
echo "B disable_ipv6(ks9) = $(ip netns exec KB cat /proc/sys/net/ipv6/conf/ks9/disable_ipv6) (ждём 0 при -tunv6)"

# клиент A с ротацией
ip netns exec KA $KS -keyfile /root/build/ks-vpn.key -tun ks8 -tunip 10.99.0.1/24 \
  -peerhost 10.0.9.254 -peerport 24509 -listen 24510 -outdir c2n -indir n2c -T 8 \
  -tunv6 -v6prefix $POOL -v6rot 2 > $LOGD/A.log 2>&1 &
sleep 2
ip netns exec KA ip -6 route replace default dev ks8
echo "A disable_ipv6(ks8) = $(ip netns exec KA cat /proc/sys/net/ipv6/conf/ks8/disable_ipv6) (ждём 0 при -tunv6)"

# слушатель в «интернете»
cat > $LOGD/recv.py <<'EOF'
import socket, time
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.bind(('2001:db8:666::2', 9999))
s.settimeout(14)
srcs = []
t0 = time.time()
while time.time() - t0 < 12:
    try:
        d, a = s.recvfrom(2048)
        srcs.append(a[0])
        s.sendto(b'ok', a)
    except socket.timeout:
        break
print('SRCS:' + ','.join(srcs))
EOF
ip netns exec KC python3 $LOGD/recv.py > $LOGD/recv.out 2>&1 &

# отправитель на клиенте: каждый пакет — новый сокет (новый поток)
cat > $LOGD/send.py <<'EOF'
import socket, time
for i in range(9):
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.settimeout(2)
    try:
        s.sendto(b'pkt%d' % i, ('2001:db8:666::2', 9999))
        s.recvfrom(64)
    except Exception:
        pass
    s.close()
    time.sleep(1)
print('SENT_DONE')
EOF
ip netns exec KA python3 $LOGD/send.py > $LOGD/send.out 2>&1
sleep 3

echo '=== источники, увиденные «интернетом» (KC) ==='
cat $LOGD/recv.out
python3 - <<'EOF'
import ipaddress
line = open('/tmp/ksv6/recv.out').read()
srcs = []
for l in line.splitlines():
    if l.startswith('SRCS:'):
        srcs = [x for x in l[5:].split(',') if x]
pool = ipaddress.ip_network('fd6b:6b73:5b49::/48')
uniq = list(dict.fromkeys(srcs))
print('получено пакетов:', len(srcs), '; уникальных источников:', len(uniq))
ok = len(srcs) >= 6 and len(uniq) >= 3 and all(ipaddress.ip_address(s) in pool for s in srcs)
print('ROTATION_E2E:', 'PASS' if ok else 'FAIL')
EOF

echo '=== v4-регрессия: ping через туннель ==='
ip netns exec KA ping -c 2 -W 2 10.99.0.2 2>&1 | tail -2

echo '=== контроль дефолта: без -tunv6 disable_ipv6=1 ==='
ip netns exec KA pkill -x ks-vpn-linux; sleep 0.5
ip netns exec KA $KS -keyfile /root/build/ks-vpn.key -tun ks8 -tunip 10.99.0.1/24 \
  -peerhost 10.0.9.254 -peerport 24509 -listen 24510 -outdir c2n -indir n2c -T 8 > $LOGD/A2.log 2>&1 &
sleep 1
echo "без флага: disable_ipv6(ks8) = $(ip netns exec KA cat /proc/sys/net/ipv6/conf/ks8/disable_ipv6) (ждём 1)"

pkill -x ks-vpn-linux 2>/dev/null
for n in KA KB KC; do ip netns del $n 2>/dev/null; done
echo KS_V6_TEST_DONE
