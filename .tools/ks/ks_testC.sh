set +e
echo '=== ip rule (policy routing):'
ip rule list
echo '=== маршруты по всем таблицам:'
ip route list table all | grep -vE '^broadcast|^local |^multicast|^fe80|^::1' | head -25
echo '=== conntrack в ядре:'
cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo 'nf_conntrack НЕ загружен'
echo '=== tcpdump:'
which tcpdump || echo NO_TCPDUMP
echo '=== diag-счётчики forward/postrouting:'
nft add table ip ksdiag 2>/dev/null
nft add chain ip ksdiag fwd '{ type filter hook forward priority 0; }' 2>/dev/null
nft add rule ip ksdiag fwd ip saddr 10.99.0.0/24 counter
nft add rule ip ksdiag fwd ip daddr 10.99.0.0/24 counter
nft add rule ip ks_nat post ip saddr 10.99.0.0/24 oifname ens3 counter 2>/dev/null
ip netns del T1 2>/dev/null; pkill -f 'tun ks9' 2>/dev/null; ip link del vethTH 2>/dev/null; sleep 1
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
echo '=== ping 8.8.8.8 через туннель:'
ip netns exec T1 ping -I ks9 -c 4 -W 2 8.8.8.8 2>&1 | tail -2
echo '=== счётчики forward (out=saddr 10.99 / in=daddr 10.99):'
nft -a list table ip ksdiag 2>/dev/null | grep counter
echo '=== счётчик postrouting (ks_nat):'
nft -a list table ip ks_nat 2>/dev/null | grep -E 'counter|masquerade'
pkill -f 'tun ks9' 2>/dev/null; ip netns del T1 2>/dev/null; ip link del vethTH 2>/dev/null
echo TESTC_DONE
