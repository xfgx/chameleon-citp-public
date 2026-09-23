set +e
pkill -f 'tun ks9' 2>/dev/null; ip netns del T1 2>/dev/null; ip link del vethTH 2>/dev/null; sleep 1
echo '=== маршрутное решение ядра для форвардинга (iif ks0):'
ip route get 8.8.8.8 from 10.99.0.3 iif ks0 2>&1
echo '=== то же без iif:'
ip route get 8.8.8.8 from 10.99.0.3 2>&1
echo '=== netns + клиент:'
ip netns add T1
ip link add vethT1 type veth peer name vethTH
ip addr add 10.0.9.254/24 dev vethTH
ip link set vethTH up
ip link set vethT1 netns T1
ip netns exec T1 ip addr add 10.0.9.1/24 dev vethT1
ip netns exec T1 ip link set vethT1 up
ip netns exec T1 ip link set lo up
ip netns exec T1 /root/build/ks-vpn -keyfile /root/build/ks-vpn.key -tunip 10.99.0.3/24 -peerhost 10.0.9.254 -peerport 51820 -listen 24509 -tun ks9 -outdir c2n -indir n2c -T 8 > /root/build/ks-t1.log 2>&1 &
sleep 2
timeout 15 tcpdump -i ks0 -n -c 12 icmp 2>/dev/null > /root/tcp-ks0.log 2>&1 &
timeout 15 tcpdump -i ens3 -n -c 12 'icmp and host 8.8.8.8' 2>/dev/null > /root/tcp-ens3.log 2>&1 &
sleep 1
echo '=== ping 8.8.8.8 через туннель:'
ip netns exec T1 ping -I ks9 -c 3 -W 2 8.8.8.8 2>&1 | tail -2
sleep 12
echo '=== что видел ks0 (вход в ядро из туннеля + ответы ядра):'
grep -v 'listening' /root/tcp-ks0.log
echo '=== что видел ens3 (вышло ли в провод / пришло ли назад):'
grep -v 'listening' /root/tcp-ens3.log
pkill -f 'tun ks9' 2>/dev/null; ip netns del T1 2>/dev/null; ip link del vethTH 2>/dev/null
echo TESTD_DONE
