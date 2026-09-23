#!/bin/bash
# setup_hop2_ru.sh — второе плечо (RU -> зарубежный выход), аддитивно.
# Ничего из работающего первого плеча не ломает: ks1 только слушает,
# переключение экспорта делается отдельно ks-exit-on.sh.
set -eu
export PATH=/usr/sbin:/sbin:/usr/bin:/bin

RU_WAN=192.0.2.10
HOP2_PORT=51821
HOP2_NET=10.98.0.0/24
HOP2_RU=10.98.0.1/24
HOP2_PEER=10.98.0.2
CLIENT_NET=10.99.0.0/24

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BK=/root/backup/hop2-pre-$STAMP
mkdir -p "$BK"

echo "=== BACKUP -> $BK ==="
nft list ruleset            > "$BK/nft-ruleset.txt" 2>&1 || true
ip rule show                > "$BK/ip-rule.txt"     2>&1 || true
ip route show               > "$BK/ip-route-main.txt" 2>&1 || true
ip -br addr show            > "$BK/ip-addr.txt"     2>&1 || true
cp -a /etc/systemd/system/ks-vpn-node.service "$BK/" 2>/dev/null || true
cp -a /etc/systemd/system/chaossync-server.service "$BK/" 2>/dev/null || true
{ systemctl is-active ks-vpn-node   || true
  systemctl is-active chaossync-server || true; } > "$BK/services.txt" 2>&1
ln -sfn "$BK" /root/backup/hop2-pre-latest
echo "BACKUP_OK"

echo "=== 1. ключ второго плеча (отдельный от первого) ==="
if [ ! -f /root/build/ks-hop2.key ]; then
	/root/build/ks-vpn -genkey -keyfile /root/build/ks-hop2.key
else
	echo "уже существует, переиспользуем"
fi
chmod 600 /root/build/ks-hop2.key
echo "HOP2_KEY_SHA256=$(sha256sum /root/build/ks-hop2.key | cut -d' ' -f1)"

echo "=== 2. unit второго плеча (респондер на :$HOP2_PORT, интерфейс ks1) ==="
cat > /etc/systemd/system/ks-vpn-exit.service <<EOF
[Unit]
Description=Chameleon KS-VPN — hop2 responder to foreign exit node (ks1)
After=network-online.target ks-vpn-node.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/root/build
ExecStartPre=/bin/sh -c 'sysctl -w net.ipv4.ip_forward=1 >/dev/null'
ExecStart=/root/build/ks-vpn -keyfile /root/build/ks-hop2.key -tun ks1 -tunip $HOP2_RU -listen $HOP2_PORT -peerport $HOP2_PORT -outdir r2x -indir x2r -T 8
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
echo "UNIT_OK"

echo "=== 3. nft: чистка дублей + осмысленные счётчики ==="
# 8 одинаковых masquerade и недостижимый counter -> пересобираем цепочку с нуля.
# counter ДО masquerade в одном правиле => счётчик наконец достижим.
nft add table ip ks_nat 2>/dev/null || true
nft add chain ip ks_nat post '{ type nat hook postrouting priority srcnat; }' 2>/dev/null || true
nft flush chain ip ks_nat post
nft add rule ip ks_nat post ip saddr $CLIENT_NET oifname "ks1"   counter masquerade
nft add rule ip ks_nat post ip saddr $CLIENT_NET oifname "ens3" counter masquerade
nft delete table ip ksdiag 2>/dev/null || true
echo "NFT_OK"

echo "=== 4. скрипты переключения экспорта ==="
cat > /root/build/ks-exit-on.sh <<EOF
#!/bin/bash
# Направить трафик клиентов (10.99.0.0/24) на зарубежный выход через ks1.
# Fail-closed: если ks1 упал, маршрут исчезает и трафик уходит в blackhole,
# а НЕ утекает через RU (иначе — молчаливая подмена выхода).
set -eu
export PATH=/usr/sbin:/sbin:/usr/bin:/bin
if ! ip -br link show ks1 >/dev/null 2>&1; then
	echo "FAIL: ks1 отсутствует — сначала systemctl start ks-vpn-exit"; exit 1
fi
sysctl -w net.ipv4.conf.ks1.rp_filter=2 >/dev/null
sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip route replace blackhole default metric 1000 table 100
ip route replace default via $HOP2_PEER dev ks1 metric 1 table 100
ip rule del iif ks0 lookup 100 2>/dev/null || true
ip rule del iif ks0 to $RU_WAN lookup main 2>/dev/null || true
ip rule add iif ks0 to $RU_WAN lookup main priority 99
ip rule add iif ks0 lookup 100 priority 100
# снять RU-выход, чтобы не было тихой утечки мимо зарубежной ноды
for h in \$(nft -a list chain ip ks_nat post | grep 'oifname "ens3"' | grep -o 'handle [0-9]*' | awk '{print \$2}'); do
	nft delete rule ip ks_nat post handle \$h || true
done
echo "EXIT_ON: клиенты -> ks1 -> зарубежная нода; RU-выход снят"
ip rule show; ip route show table 100; nft list chain ip ks_nat post
EOF
cat > /root/build/ks-exit-off.sh <<EOF
#!/bin/bash
# Вернуть выход на RU-ноду (откат второго плеча).
set -eu
export PATH=/usr/sbin:/sbin:/usr/bin:/bin
ip rule del iif ks0 lookup 100 2>/dev/null || true
ip rule del iif ks0 to $RU_WAN lookup main 2>/dev/null || true
ip route flush table 100 2>/dev/null || true
if ! nft list chain ip ks_nat post | grep -q 'oifname "ens3"'; then
	nft add rule ip ks_nat post ip saddr $CLIENT_NET oifname "ens3" counter masquerade
fi
echo "EXIT_OFF: выход снова RU"
ip rule show; nft list chain ip ks_nat post
EOF
chmod +x /root/build/ks-exit-on.sh /root/build/ks-exit-off.sh
echo "SCRIPTS_OK"

echo "=== 5. запуск второго плеча (пока только слушает) ==="
systemctl enable ks-vpn-exit >/dev/null 2>&1 || true
systemctl restart ks-vpn-exit
sleep 3
systemctl is-active ks-vpn-exit
echo "=== VERIFY ==="
echo "--- links ---";  ip -br addr show
echo "--- listen ---"; ss -lunp | grep -E "51820|51821|4500" || true
echo "--- nft ---";    nft list chain ip ks_nat post
echo "--- rules (должны быть только дефолтные, переключение ещё не делали) ---"; ip rule show
echo "--- first leg still alive ---"; systemctl is-active ks-vpn-node
echo "--- exit leg log ---"; journalctl -u ks-vpn-exit -n 8 --no-pager
echo "SETUP_HOP2_DONE"
