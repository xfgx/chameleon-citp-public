#!/bin/bash
# ks-hub-net.sh - сетевая обвязка многопользовательского хаба KS (ks-hub).
#   up   - политика маршрутизации + NAT для сети хаба
#   down - снять всё, что добавил up
# Идемпотентно: повторный up ничего не дублирует.
set -u
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

HUB_IF="${HUB_IF:-kshub0}"
HUB_NET="${HUB_NET:-10.99.9.0/24}"
NODE_IP="${NODE_IP:-192.0.2.10}"
EXIT_IF="${EXIT_IF:-ks1}"
WAN_IF="${WAN_IF:-ens3}"
PREF_WIRE=102
PREF_TUN=103
TABLE_EXIT=100
HUB_V6_POOL="${HUB_V6_POOL:-2001:db8:1::/52}"
V6_PREF=104
WAIT_IF_SEC="${WAIT_IF_SEC:-15}"

log() { echo "ks-hub-net: $*"; }

wait_iface() {
  local i=0
  while [ "$i" -lt "$WAIT_IF_SEC" ]; do
    if ip link show "$HUB_IF" >/dev/null 2>&1; then return 0; fi
    sleep 1
    i=$((i+1))
  done
  return 1
}

rule_present() { # $1=pref $2=подстрока
  ip rule show pref "$1" 2>/dev/null | grep -q "$2"
}

v6_rule_present() {
  ip -6 rule show pref "$1" 2>/dev/null | grep -q "$2"
}

nft_ensure_table() {
  nft list table ip ks_nat >/dev/null 2>&1 && return 0
  nft add table ip ks_nat || return 1
  nft add chain ip ks_nat post '{ type nat hook postrouting priority srcnat ; policy accept ; }'
}

nft_rule_present() { # $1=oifname
  nft list chain ip ks_nat post 2>/dev/null | grep -q "ip saddr $HUB_NET .*oifname \"$1\""
}

up() {
  wait_iface || { log "интерфейс $HUB_IF не появился за ${WAIT_IF_SEC}s - обвязка не применена"; exit 1; }
  sysctl -qw net.ipv4.ip_forward=1 2>/dev/null || true
  sysctl -qw net.ipv4.conf.all.rp_filter=2 2>/dev/null || true
  sysctl -qw "net.ipv4.conf.$HUB_IF.rp_filter=2" 2>/dev/null || true

  # 1) ответы на сам провод (UDP на публичный IP ноды) - основная таблица
  if rule_present "$PREF_WIRE" "$HUB_IF"; then
    log "правило pref $PREF_WIRE уже есть"
  else
    ip rule add pref "$PREF_WIRE" to "$NODE_IP" iif "$HUB_IF" lookup main && log "+ ip rule pref $PREF_WIRE (to $NODE_IP iif $HUB_IF -> main)"
  fi

  # IPv6: each user owns one /64 inside our routed /48. The more-specific
  # /52 route wins over the legacy /48 -> ks0 route.
  v6ok=0
  v6err=""
  for i in $(seq 1 10); do
    if v6err=$(ip -6 route replace "$HUB_V6_POOL" dev "$HUB_IF" 2>&1); then
      v6ok=1
      break
    fi
    sleep 1
  done
  if [ "$v6ok" -ne 1 ]; then
    log "ОШИБКА: IPv6-маршрут $HUB_V6_POOL -> $HUB_IF не поднялся: $v6err"
    return 1
  fi
  if v6_rule_present "$V6_PREF" "$HUB_IF"; then
    log "IPv6 правило pref $V6_PREF уже есть"
  else
    ip -6 rule add pref "$V6_PREF" iif "$HUB_IF" lookup "$TABLE_EXIT" && log "+ ip -6 rule pref $V6_PREF (iif $HUB_IF -> table $TABLE_EXIT)"
  fi
  nft list table ip6 ks6g >/dev/null 2>&1 || nft add table ip6 ks6g
  nft list chain ip6 ks6g guard6 >/dev/null 2>&1 || nft add chain ip6 ks6g guard6 '{ type filter hook forward priority 0; policy accept; }'
  if ! nft list chain ip6 ks6g guard6 2>/dev/null | grep -q "iifname \"$HUB_IF\" ip6 saddr != $HUB_V6_POOL"; then
    nft add rule ip6 ks6g guard6 iifname "$HUB_IF" ip6 saddr != "$HUB_V6_POOL" counter drop
  fi

  # 2) остальной трафик клиентов - во вторую ногу (таблица 100 -> ks1)
  if rule_present "$PREF_TUN" "$HUB_IF"; then
    log "правило pref $PREF_TUN уже есть"
  else
    ip rule add pref "$PREF_TUN" iif "$HUB_IF" lookup "$TABLE_EXIT" && log "+ ip rule pref $PREF_TUN (iif $HUB_IF -> table $TABLE_EXIT)"
  fi

  nft_ensure_table || log "ВНИМАНИЕ: не удалось создать таблицу ip ks_nat"
  for oif in "$EXIT_IF" "$WAN_IF"; do
    if nft_rule_present "$oif"; then
      log "nft masquerade $HUB_NET -> $oif уже есть"
    else
      nft add rule ip ks_nat post ip saddr "$HUB_NET" oifname "\"$oif\"" masquerade && log "+ nft masquerade $HUB_NET -> $oif"
    fi
  done
  log "up готово"
}

down() {
  local p h handles
  while ip -6 rule show pref "$V6_PREF" 2>/dev/null | grep -q "$HUB_IF"; do
    ip -6 rule del pref "$V6_PREF" 2>/dev/null || break
    log "- ip -6 rule pref $V6_PREF"
  done
  ip -6 route del "$HUB_V6_POOL" dev "$HUB_IF" 2>/dev/null || true
  for h in $(nft -a list chain ip6 ks6g guard6 2>/dev/null | grep "iifname \"$HUB_IF\"" | grep -oE 'handle [0-9]+' | awk '{print $2}' | sort -rn); do
    nft delete rule ip6 ks6g guard6 handle "$h" 2>/dev/null || true
  done
  for p in "$PREF_TUN" "$PREF_WIRE"; do
    while ip rule show pref "$p" 2>/dev/null | grep -q "$HUB_IF"; do
      ip rule del pref "$p" 2>/dev/null || break
      log "- ip rule pref $p"
    done
  done
  handles=$(nft -a list chain ip ks_nat post 2>/dev/null | grep "ip saddr $HUB_NET" | grep -oE 'handle [0-9]+' | awk '{print $2}' | sort -rn)
  for h in $handles; do
    nft delete rule ip ks_nat post handle "$h" 2>/dev/null && log "- nft rule handle $h"
  done
  log "down готово"
}

case "${1:-}" in
  up)   up ;;
  down) down ;;
  *)    echo "usage: $0 up|down" >&2; exit 2 ;;
esac
