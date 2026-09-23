#!/bin/bash
# v6rot-myserv.sh — 6in4 + v6-транзит пула на выходе Myserv (198.51.100.10).
# Поднимает he6in4 (193.0.203.203 <-> 198.51.100.10, ::2/64, default via ::1),
# форвардинг v6, возврат пула /48 в exit-TUN (ks0 -> RU), anti-spoof гард,
# новый ks-vpn с -tunv6. Бэкап -> /root/backup/v6rot-pre-<ts>.
set -eu
export PATH=/usr/sbin:/sbin:/usr/bin:/bin
POOL=2001:db8:1::/48
TUN6=2001:db8:1::2/64
BR6=2001:db8:1::1
BR4=193.0.203.203
MY4=198.51.100.10
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BK=/root/backup/v6rot-pre-$STAMP
mkdir -p "$BK"

echo "=== BACKUP -> $BK ==="
cp -a /usr/local/bin/ks-vpn "$BK/ks-vpn.bin" 2>/dev/null || true
cp -a /etc/systemd/system/ks-vpn-exit.service "$BK/" 2>/dev/null || true
cp -a /etc/systemd/system/he6in4.service "$BK/" 2>/dev/null || true
ip -6 route show > "$BK/ip6-route.txt" 2>&1 || true
iptables-save > "$BK/iptables.txt" 2>&1 || true
ip6tables-save > "$BK/ip6tables.txt" 2>&1 || true
nft list ruleset > "$BK/nft.txt" 2>&1 || true
ln -sfn "$BK" /root/backup/v6rot-pre-latest
echo BACKUP_OK

echo "=== 0. доступность брокера (v4) ==="
ping -c 2 -W 2 $BR4 2>&1 | tail -2 || true

echo "=== 1. 6in4 (идемпотентно) ==="
modprobe sit 2>/dev/null || true
ip tunnel show he6in4 >/dev/null 2>&1 && ip tunnel del he6in4 || true
ip tunnel add he6in4 mode sit remote $BR4 local $MY4 ttl 64
ip link set he6in4 up mtu 1480
ip -6 addr add $TUN6 dev he6in4 2>/dev/null || true
ip -6 route replace ::/0 via $BR6 dev he6in4
sysctl -qw net.ipv6.conf.all.forwarding=1
echo 'net.ipv6.conf.all.forwarding=1' > /etc/sysctl.d/99-ks-v6.conf
ip -6 addr show dev he6in4 | grep inet6 || true

echo "=== 2. файрвол: proto-41 inbound + icmp6 ==="
# Docker-хост: iptables. Разрешаем 6in4 от брокера и ICMPv6 (PMTU!).
iptables -C INPUT -p 41 -s $BR4 -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p 41 -s $BR4 -j ACCEPT
ip6tables -C INPUT -p ipv6-icmp -j ACCEPT 2>/dev/null || ip6tables -I INPUT 1 -p ipv6-icmp -j ACCEPT
ip6tables -C FORWARD -i ks0 -o he6in4 -j ACCEPT 2>/dev/null || ip6tables -I FORWARD 1 -i ks0 -o he6in4 -j ACCEPT
ip6tables -C FORWARD -i he6in4 -o ks0 -j ACCEPT 2>/dev/null || ip6tables -I FORWARD 1 -i he6in4 -o ks0 -j ACCEPT
echo FW_OK

echo "=== 3. проверка туннеля ==="
ping -6 -c 2 -W 3 $BR6 2>&1 | tail -2
ping -6 -c 2 -W 3 2001:4860:4860::8888 2>&1 | tail -2

echo "=== 4. persistence: he6in4.service ==="
cat > /etc/systemd/system/he6in4.service <<EOS
[Unit]
Description=6in4 tunnel to broker $BR4 (routed /48)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'modprobe sit 2>/dev/null || true; ip tunnel show he6in4 >/dev/null 2>&1 || ip tunnel add he6in4 mode sit remote $BR4 local $MY4 ttl 64; ip link set he6in4 up mtu 1480; ip -6 addr add $TUN6 dev he6in4 2>/dev/null || true; ip -6 route replace ::/0 via $BR6 dev he6in4; sysctl -qw net.ipv6.conf.all.forwarding=1'
ExecStop=/bin/sh -c 'ip -6 route del ::/0 via $BR6 dev he6in4 2>/dev/null || true; ip tunnel del he6in4 2>/dev/null || true'

[Install]
WantedBy=multi-user.target
EOS
systemctl daemon-reload
systemctl enable he6in4 >/dev/null 2>&1 || true
echo UNIT_6IN4_OK

echo "=== 5. exit-плечо: новый бинарь + -tunv6 + возврат пула ==="
install -m 0755 /root/v6rot-build/ks-vpn-linux /usr/local/bin/ks-vpn.new
mv /usr/local/bin/ks-vpn.new /usr/local/bin/ks-vpn
cat > /usr/local/sbin/ks-v6exit.sh <<'EOS'
#!/bin/bash
# Ждём exit-TUN ks0 (плечо к RU); возврат пула клиента -> в туннель;
# anti-spoof: из туннеля принимаем только источники нашего /48.
set -u
export PATH=/usr/sbin:/sbin:/usr/bin:/bin
POOL=2001:db8:1::/48
for i in $(seq 1 30); do ip -br link show ks0 >/dev/null 2>&1 && break; sleep 0.3; done
sysctl -qw net.ipv6.conf.all.forwarding=1
ip -6 route replace $POOL dev ks0
nft add table ip6 ks6g 2>/dev/null || true
nft add chain ip6 ks6g guard6 '{ type filter hook forward priority 0; policy accept; }' 2>/dev/null || true
nft flush chain ip6 ks6g guard6
nft add rule ip6 ks6g guard6 iifname "ks0" ip6 saddr != $POOL counter drop
exit 0
EOS
chmod +x /usr/local/sbin/ks-v6exit.sh
sed -i 's| -T 8$| -T 8 -tunv6|' /etc/systemd/system/ks-vpn-exit.service
grep -q 'ks-v6exit.sh' /etc/systemd/system/ks-vpn-exit.service || \
  sed -i '/^ExecStart=/a ExecStartPost=/usr/local/sbin/ks-v6exit.sh' /etc/systemd/system/ks-vpn-exit.service
systemctl daemon-reload
systemctl restart ks-vpn-exit
sleep 3
systemctl is-active ks-vpn-exit

echo "=== VERIFY ==="
ss -lunp | grep 51821 || true
ip -6 route show | grep -E '2a03|default' || true
ip tunnel show he6in4
nft list chain ip6 ks6g guard6 2>/dev/null || true
journalctl -u ks-vpn-exit -n 3 --no-pager | grep -o 'стадии.*' || true
echo V6ROT_MYSERV_DONE
