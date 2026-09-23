#!/bin/bash
# ks-v6exithop.sh — ExecStartPost для ks-vpn-exit (RU-нода).
# Ждём TUN ks1 плеча выхода и восстанавливаем ОБА семейства в table 100:
# маршруты через TUN умирают при пересоздании интерфейса (рестарт сервиса) —
# именно это 2026-09-04 уронило v4-выход (v4 default пропал, v6 вернули,
# v4 забыли). Exit OFF -> ks-exit-off.sh снимает всё (fail-closed blackhole).
# Скрипт обязан всегда завершаться нулём (иначе systemd роняет юнит).
set -u
export PATH=/usr/sbin:/sbin:/usr/bin:/bin
for i in $(seq 1 40); do ip -br link show ks1 >/dev/null 2>&1 && break; sleep 0.25; done
sysctl -qw net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
sysctl -qw net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
ip route replace blackhole default metric 1000 table 100 2>/dev/null || true
ip route replace default via 10.98.0.2 dev ks1 metric 1 table 100 2>/dev/null || true
ip rule del iif ks0 lookup 100 2>/dev/null || true
ip rule add iif ks0 lookup 100 priority 100 2>/dev/null || true
ip -6 route replace blackhole default metric 1000 table 100 2>/dev/null || true
ip -6 route replace default dev ks1 metric 1 table 100 2>/dev/null || true
ip -6 rule del iif ks0 lookup 100 2>/dev/null || true
ip -6 rule add iif ks0 lookup 100 priority 100 2>/dev/null || true
exit 0
