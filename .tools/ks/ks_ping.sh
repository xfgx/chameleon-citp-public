set -e
cd /root/build
ip netns del A 2>/dev/null || true
ip netns del B 2>/dev/null || true
pkill -x ks-vpn 2>/dev/null || true
sleep 1
ip netns add A
ip netns add B
ip link add vethA type veth peer name vethB
ip link set vethA netns A
ip link set vethB netns B
ip netns exec A ip addr add 10.0.0.1/24 dev vethA
ip netns exec A ip link set vethA up
ip netns exec A ip link set lo up
ip netns exec B ip addr add 10.0.0.2/24 dev vethB
ip netns exec B ip link set vethB up
ip netns exec B ip link set lo up
# нода B: слушает 24000 (c2n), шлёт на A:24001
ip netns exec B ./ks-vpn -keyfile /root/build/cb.key -tunip 10.99.0.2/24 -peerhost 10.0.0.1 -listen 24000 -peerport 24001 -outdir n2c -indir c2n -T 8 > ks-node.log 2>&1 &
sleep 1
# клиент A: слушает 24001 (n2c), шлёт на B:24000
ip netns exec A ./ks-vpn -keyfile /root/build/cb.key -tunip 10.99.0.1/24 -peerhost 10.0.0.2 -listen 24001 -peerport 24000 -outdir c2n -indir n2c -T 8 > ks-client.log 2>&1 &
sleep 2
echo '=== мосты подняты ==='
echo '--- ks-node.log ---'; head -3 ks-node.log
echo '--- ks-client.log ---'; head -3 ks-client.log
echo '=== PING через KS-туннель (10.99.0.1 -> 10.99.0.2) ==='
ip netns exec A ping -c 4 -W 3 10.99.0.2 2>&1 || echo 'PING FAILED'
echo '=== probe-invisibility: мусор на порт ноды (5 датаграмм) ==='
ip netns exec A bash -c 'for i in 1 2 3 4 5; do echo "garbage-probe-$i" > /dev/udp/10.0.0.2/24000; done' || true
sleep 3
echo '--- счётчики ноды (dropped растёт, ответов мусору нет) ---'
tail -2 ks-node.log
echo '=== контроль: туннель жив после активных проб ==='
ip netns exec A ping -c 2 -W 3 10.99.0.2 2>&1 || echo 'PING2 FAILED'
echo '=== LOSS 10% + ротация эпох (20 пакетов x 1.5с = ~30с, T=8 -> ~4 ротации) ==='
ip netns exec A tc qdisc add dev vethA root netem loss 10% 2>/dev/null || echo 'tc netem недоступен — честно пропускаю искусственные потери'
ip netns exec A ping -c 20 -i 1.5 10.99.0.2 2>&1 | tail -4 || true
echo '--- финальные счётчики клиента ---'
tail -2 ks-client.log
echo KS_PING_DONE
