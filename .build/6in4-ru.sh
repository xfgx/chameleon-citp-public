#!/bin/bash
# 6in4-ru.sh — 6in4 на RU-ноде (192.0.2.10): routed /48 2001:db8:2::/48.
# Это ПРОВОД-пул ноды для KS: нода слушает весь пул (anyip на lo), отвечает с
# hit-адреса (pktinfo+FREEBIND в бинаре). Отделён от клиентского пула Myserv
# (5b49::/48): правило приоритета 50 отправляет src∈5b4a & dst∈5b49 ТОЛЬКО в
# he6in4ru (table 101) — иначе собственные ответы ноды попадают в ks0 и
# зацикливаются в TUN (инцидент 2026-09-04: 70k пакетов/с).
set -eu
export PATH=/usr/sbin:/sbin:/usr/bin:/bin
modprobe sit 2>/dev/null || true
ip tunnel show he6in4ru >/dev/null 2>&1 || ip tunnel add he6in4ru mode sit remote 193.0.203.203 local 192.0.2.10 ttl 64
ip link set he6in4ru up mtu 1480
ip -6 addr add 2001:db8:2::2/64 dev he6in4ru 2>/dev/null || true
ip -6 route replace ::/0 dev he6in4ru
ip -6 route replace local 2001:db8:2::/48 dev lo
ip -6 route replace default dev he6in4ru table 101
ip -6 rule del from 2001:db8:2::/48 to 2001:db8:1::/48 lookup 101 2>/dev/null || true
ip -6 rule add from 2001:db8:2::/48 to 2001:db8:1::/48 lookup 101 priority 50
echo "6IN4_RU_OK"
ip -6 route show table 101; ip -6 rule show | grep 5b4a
