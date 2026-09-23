set +e
pkill -f 'tun ks9' 2>/dev/null
ip netns del T1 2>/dev/null
ip link del vethTH 2>/dev/null
ip link del ks1 2>/dev/null
sleep 1
echo '=== iptables FORWARD policy:'
iptables -L FORWARD -n -v 2>/dev/null | head -3
iptables-legacy -L FORWARD -n -v 2>/dev/null | head -3
ufw status 2>/dev/null | head -2
echo '=== netns setup:'
ip netns add T1 || echo NETNS_ADD_FAIL
ip link add vethT1 type veth peer name vethTH || echo VETH_FAIL
ip addr add 10.0.9.254/24 dev vethTH
ip link set vethTH up
ip link set vethT1 netns T1
ip netns exec T1 ip addr add 10.0.9.1/24 dev vethT1
ip netns exec T1 ip link set vethT1 up
ip netns exec T1 ip link set lo up
echo NETNS_OK
ip netns exec T1 /root/build/ks-vpn -keyfile /root/build/ks-vpn.key -tunip 10.99.0.3/24 -peerhost 10.0.9.254 -peerport 51820 -listen 24509 -tun ks9 -outdir c2n -indir n2c -T 8 > /root/build/ks-t1.log 2>&1 &
sleep 2
echo '=== ks0 stats ДО (RX=записано из туннеля / TX=ядро отвечает):'
ip -s link show ks0 | grep -A1 'RX:' | tail -1
ip -s link show ks0 | grep -A1 'TX:' | tail -1
echo '=== ping 10.99.0.2 через сервис (ядро ноды отвечает в TUN?):'
ip netns exec T1 ping -c 3 -W 2 10.99.0.2 2>&1 | tail -2
echo '=== ping 8.8.8.8 через сервис (forward+NAT+internet+return):'
ip netns exec T1 ping -I ks9 -c 3 -W 2 8.8.8.8 2>&1 | tail -2
echo '=== лог тест-клиента:'
tail -4 /root/build/ks-t1.log
echo '=== сервис:'
journalctl -u ks-vpn-node -n 2 --no-pager | grep -o 'стадии.*'
echo '=== ks0 stats ПОСЛЕ:'
ip -s link show ks0 | grep -A1 'RX:' | tail -1
ip -s link show ks0 | grep -A1 'TX:' | tail -1
echo '=== conntrack 10.99:'
which conntrack >/dev/null 2>&1 && conntrack -L 2>/dev/null | grep 10.99 | head -4 || echo 'conntrack не установлен'
pkill -f 'tun ks9' 2>/dev/null
ip netns del T1 2>/dev/null
ip link del vethTH 2>/dev/null
echo TESTB_DONE
