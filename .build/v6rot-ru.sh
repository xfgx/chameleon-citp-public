#!/bin/bash
# v6rot-ru.sh — деплой v6-транзита /48 на RU-ноду (192.0.2.10).
# Бэкап -> /root/backup/v6rot-pre-<ts>; откат — восстановить бинарь и unit'ы.
# Аддитивно: v4-поведение не меняется, chaossync-server не трогаем.
set -eu
export PATH=/usr/sbin:/sbin:/usr/bin:/bin
POOL=2001:db8:1::/48
B=/root/build/v6rot-20260904
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BK=/root/backup/v6rot-pre-$STAMP
mkdir -p "$BK"

echo "=== BACKUP -> $BK ==="
cp -a /root/build/ks-vpn "$BK/ks-vpn.bin"
cp -a /etc/systemd/system/ks-vpn-node.service "$BK/" 2>/dev/null || true
cp -a /etc/systemd/system/ks-vpn-exit.service "$BK/" 2>/dev/null || true
cp -a /root/build/ks-exit-on.sh /root/build/ks-exit-off.sh "$BK/" 2>/dev/null || true
ip -6 route show > "$BK/ip6-route.txt" 2>&1 || true
ip -6 rule show  > "$BK/ip6-rule.txt"  2>&1 || true
nft list ruleset > "$BK/nft.txt" 2>&1 || true
ln -sfn "$BK" /root/backup/v6rot-pre-latest
echo BACKUP_OK

echo "=== 1. новый бинарь (sha ниже) ==="
sha256sum "$B/ks-vpn-linux"
install -m 0755 "$B/ks-vpn-linux" /root/build/ks-vpn.new
mv /root/build/ks-vpn.new /root/build/ks-vpn

echo "=== 2. скрипты v6-маршрутизации (ExecStartPost) ==="
cat > /root/build/ks-v6node.sh <<'EOS'
#!/bin/bash
# Ждём TUN ks0 клиентского плеча, включаем v6-форвардинг, заводим пул клиента
# (возвратный трафик интернет->пул) и anti-spoof гард: из туннеля принимаем
# только источники нашего /48 (чужие source-адреса — drop, мы не усилитель).
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
cat > /root/build/ks-v6exithop.sh <<'EOS'
#!/bin/bash
# Ждём TUN ks1 плеча выхода; восстанавливаем ОБА семейства в table 100:
# маршруты через TUN умирают при пересоздании интерфейса (рестарт сервиса) —
# именно это 2026-09-04 уронило v4-выход (v4 default пропал, v6 вернули,
# v4 забыли). Exit OFF -> ks-exit-off.sh снимает всё (fail-closed).
set -u
export PATH=/usr/sbin:/sbin:/usr/bin:/bin
for i in $(seq 1 30); do ip -br link show ks1 >/dev/null 2>&1 && break; sleep 0.3; done
sysctl -qw net.ipv6.conf.all.forwarding=1
ip route replace blackhole default metric 1000 table 100
ip route replace default via 10.98.0.2 dev ks1 metric 1 table 100
ip rule del iif ks0 lookup 100 2>/dev/null || true
ip rule add iif ks0 lookup 100 priority 100
ip -6 route replace blackhole default metric 1000 table 100
ip -6 route replace default dev ks1 metric 1 table 100
ip -6 rule del iif ks0 lookup 100 2>/dev/null || true
ip -6 rule add iif ks0 lookup 100 priority 100
exit 0
EOS
chmod +x /root/build/ks-v6node.sh /root/build/ks-v6exithop.sh
echo SCRIPTS_OK

echo "=== 3. unit'ы: -tunv6 + v6-форвардинг + ExecStartPost ==="
cat > /etc/systemd/system/ks-vpn-node.service <<'EOS'
[Unit]
Description=Chameleon KS-VPN node (ks0, client leg)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/root/build
ExecStartPre=/bin/sh -c 'sysctl -w net.ipv4.ip_forward=1; nft add table ip ks_nat 2>/dev/null || true; nft add chain ip ks_nat post "{ type nat hook postrouting priority srcnat; }" 2>/dev/null || true; nft add rule ip ks_nat post ip saddr 10.99.0.0/24 oifname ens3 masquerade 2>/dev/null || true'
ExecStartPre=/bin/sh -c 'sysctl -w net.ipv6.conf.all.forwarding=1'
ExecStart=/root/build/ks-vpn -keyfile /root/build/ks-vpn.key -tunip 10.99.0.2/24 -peerport 23500 -listen 51820 -outdir n2c -indir c2n -T 8 -tunv6
ExecStartPost=/root/build/ks-v6node.sh
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOS
cat > /etc/systemd/system/ks-vpn-exit.service <<'EOS'
[Unit]
Description=Chameleon KS-VPN — hop2 responder to foreign exit node (ks1)
After=network-online.target ks-vpn-node.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/root/build
ExecStartPre=/bin/sh -c 'sysctl -w net.ipv4.ip_forward=1 >/dev/null'
ExecStartPre=/bin/sh -c 'sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null'
ExecStart=/root/build/ks-vpn -keyfile /root/build/ks-hop2.key -tun ks1 -tunip 10.98.0.1/24 -listen 51821 -peerport 51821 -outdir r2x -indir x2r -T 8 -tunv6
ExecStartPost=/root/build/ks-v6exithop.sh
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOS
systemctl daemon-reload
echo UNITS_OK

echo "=== 4. переключатель exit on/off: v6-составляющая ==="
cat > /root/build/ks-exit-on.sh <<'EOS'
#!/bin/bash
# Направить трафик клиентов (10.99.0.0/24 + v6-пул /48) на зарубежный выход.
# Fail-closed: если ks1 упал, маршрут исчезает и трафик уходит в blackhole.
set -eu
export PATH=/usr/sbin:/sbin:/usr/bin:/bin
RU_WAN=192.0.2.10
HOP2_PEER=10.98.0.2
if ! ip -br link show ks1 >/dev/null 2>&1; then
	echo "FAIL: ks1 отсутствует — сначала systemctl start ks-vpn-exit"; exit 1
fi
sysctl -w net.ipv4.conf.ks1.rp_filter=2 >/dev/null
sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
ip route replace blackhole default metric 1000 table 100
ip route replace default via $HOP2_PEER dev ks1 metric 1 table 100
ip rule del iif ks0 lookup 100 2>/dev/null || true
ip rule del iif ks0 to $RU_WAN lookup main 2>/dev/null || true
ip rule add iif ks0 to $RU_WAN lookup main priority 99
ip rule add iif ks0 lookup 100 priority 100
ip -6 route replace blackhole default metric 1000 table 100
ip -6 route replace default dev ks1 metric 1 table 100
ip -6 rule del iif ks0 lookup 100 2>/dev/null || true
ip -6 rule add iif ks0 lookup 100 priority 100
# снять RU-выход v4, чтобы не было тихой утечки мимо зарубежной ноды
for h in $(nft -a list chain ip ks_nat post | grep 'oifname "ens3"' | grep -o 'handle [0-9]*' | awk '{print $2}'); do
	nft delete rule ip ks_nat post handle $h || true
done
echo "EXIT_ON: клиенты (v4+v6) -> ks1 -> зарубежная нода; RU-выход v4 снят"
ip rule show; ip -6 rule show; ip route show table 100; ip -6 route show table 100
EOS
cat > /root/build/ks-exit-off.sh <<'EOS'
#!/bin/bash
# Вернуть выход на RU-ноду (откат второго плеча). v6 при этом обрывается
# fail-closed (у RU нет своего v6-аплинка — честно, без утечек).
set -eu
export PATH=/usr/sbin:/sbin:/usr/bin:/bin
ip rule del iif ks0 lookup 100 2>/dev/null || true
ip rule del iif ks0 to 192.0.2.10 lookup main 2>/dev/null || true
ip route flush table 100 2>/dev/null || true
ip -6 rule del iif ks0 lookup 100 2>/dev/null || true
ip -6 route flush table 100 2>/dev/null || true
if ! nft list chain ip ks_nat post | grep -q 'oifname "ens3"'; then
	nft add rule ip ks_nat post ip saddr 10.99.0.0/24 oifname "ens3" counter masquerade
fi
echo "EXIT_OFF: выход снова RU (v4); v6-экспорт снят"
ip rule show; ip -6 rule show; nft list chain ip ks_nat post
EOS
chmod +x /root/build/ks-exit-on.sh /root/build/ks-exit-off.sh
echo SWITCH_OK

echo "=== 5. перезапуск плеч (короткий обрыв туннеля) ==="
systemctl restart ks-vpn-exit
sleep 2
systemctl restart ks-vpn-node
sleep 3
systemctl is-active ks-vpn-node ks-vpn-exit

echo "=== VERIFY ==="
ss -lunp | grep -E '51820|51821' || true
ip -6 route show | grep -E '2a03' || true
ip -6 rule show | grep ks0 || true
ip -6 route show table 100
nft list chain ip6 ks6g guard6 2>/dev/null || true
cat /proc/sys/net/ipv6/conf/ks0/disable_ipv6 /proc/sys/net/ipv6/conf/ks1/disable_ipv6
journalctl -u ks-vpn-node -n 3 --no-pager | grep -o 'стадии.*' || true
echo V6ROT_RU_DONE
