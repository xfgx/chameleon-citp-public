#!/bin/sh
# ks_wire4_probe.sh — стенд симметрии для «портового провода» (2026-09-04).
#
# Вопрос, на который отвечает стенд: если клиент бьёт со случайного
# порта на СЛУЧАЙНЫЙ адрес ноды и СЛУЧАЙНЫЙ порт (нода собирает весь
# диапазон в один сокет через nft redirect) — придёт ли ответ С ТОГО ЖЕ
# адреса И ПОРТА. Если нет — роутер клиента отбросит ответы и схему
# внедрять нельзя.
#
# ВСЁ в netns: прод на хосте (ks-vpn-node, nft ks_nat/ks6g) НЕ трогается.
#   W4A — клиент, W4B — «нода» с ДВУМЯ адресами (как .193 и .200 в бою).
#
# Запуск: PROBE=/root/build/probe4hit sh .tools/ks/ks_wire4_probe.sh

PROBE=${PROBE:-/root/build/probe4hit}
SRVPORT=39999
LOG=/tmp/ksw4/srv.log

mkdir -p /tmp/ksw4
rm -f "$LOG"

cleanup() {
	ip netns pids W4B 2>/dev/null | xargs -r kill 2>/dev/null
	ip netns del W4A 2>/dev/null
	ip netns del W4B 2>/dev/null
}
cleanup

if [ ! -x "$PROBE" ]; then
	echo "NO_PROBE $PROBE"
	exit 1
fi

echo "=== стенд: W4A (клиент) <-> W4B (нода, 2 адреса) ==="
ip netns add W4A || exit 1
ip netns add W4B || exit 1
ip link add w4a netns W4A type veth peer name w4b netns W4B || exit 1
ip -n W4A addr add 10.7.0.1/24 dev w4a
ip -n W4A link set lo up
ip -n W4A link set w4a up
ip -n W4B addr add 10.7.0.2/24 dev w4b
ip -n W4B addr add 10.7.0.3/24 dev w4b
ip -n W4B link set lo up
ip -n W4B link set w4b up

echo "=== nft redirect в W4B: udp dport 30000-30999 -> :$SRVPORT ==="
ip netns exec W4B nft add table ip w4 || echo NFT_TABLE_FAIL
ip netns exec W4B nft add chain ip w4 pre '{ type nat hook prerouting priority dstnat ; policy accept ; }' || echo NFT_CHAIN_FAIL
ip netns exec W4B nft add rule ip w4 pre udp dport 30000-30999 counter redirect to :$SRVPORT || echo NFT_RULE_FAIL

echo "=== сервер в W4B ==="
ip netns exec W4B "$PROBE" srv $SRVPORT 25 >"$LOG" 2>&1 &
sleep 1

echo "=== ТЕСТ 1: прямой на 10.7.0.2:$SRVPORT (без redirect) ==="
ip netns exec W4A "$PROBE" cli 10.7.0.2 $SRVPORT

echo "=== ТЕСТ 2: второй адрес ноды 10.7.0.3:$SRVPORT (без redirect) ==="
ip netns exec W4A "$PROBE" cli 10.7.0.3 $SRVPORT

echo "=== ТЕСТ 3: случайные порты через redirect ==="
for t in "10.7.0.2 30007" "10.7.0.3 30123" "10.7.0.2 30999" "10.7.0.3 30000"; do
	set -- $t
	ip netns exec W4A "$PROBE" cli "$1" "$2"
done

sleep 1
echo "=== счётчик redirect (должен быть 4 пакета) ==="
ip netns exec W4B nft list table ip w4 | grep -i counter

echo "=== журнал сервера ==="
cat "$LOG"

echo "=== ИТОГ ==="
echo "SYMMETRIC ответов: $(grep -c SYMMETRIC "$LOG" 2>/dev/null)"

cleanup
echo KS_WIRE4_PROBE_DONE
