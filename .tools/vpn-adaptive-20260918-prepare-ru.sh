#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ $(hostname) == your-node.example.com ]] || { printf 'Wrong build host\n' >&2; exit 1; }
ROOT=/root/vpn
RUN=vpn-adaptive-20260918-01
WORK=/root/build/$RUN
BACKUP=/root/backup/$RUN
ls -ld /root/build /root/backup "$ROOT"
[[ ! -e $WORK/src/go.mod && ! -e $BACKUP/source-before.tar.gz && ! -e $BACKUP/runtime-before.tar.gz ]] || { printf 'Source or backup already exists; refusing overwrite\n' >&2; exit 1; }
[[ $(df -Pk /root | awk 'NR==2 {print $4}') -ge 3145728 ]] || { printf 'Less than 3 GiB free\n' >&2; exit 1; }
mkdir -p -m 700 "$WORK" "$BACKUP"
mkdir -p -m 700 "$WORK/src" "$WORK/results" "$WORK/artifacts" "$BACKUP/runtime" "$BACKUP/runtime/bin" "$BACKUP/runtime/units"
paths=(go.mod go.sum internal cmd tools mobilecore scripts agent.md)
for optional in lib packaging protocol; do if [[ -e $ROOT/$optional ]]; then paths+=("$optional"); fi; done
for path in "${paths[@]}"; do [[ -e $ROOT/$path ]] || { printf 'Missing source path: %s\n' "$path" >&2; exit 1; }; done
tar -czf "$BACKUP/source-before.tar.gz" -C "$ROOT" "${paths[@]}"
tar -tzf "$BACKUP/source-before.tar.gz" >/dev/null
tar -xzf "$BACKUP/source-before.tar.gz" -C "$WORK/src"
for unit in cham-server ks-vpn-node chaossync-server; do
  systemctl is-active --quiet "$unit"
  pid=$(systemctl show "$unit" -p MainPID --value)
  binary=$(readlink -f "/proc/$pid/exe")
  [[ -f $binary ]] || exit 1
  cp --preserve=mode,timestamps -- "$binary" "$BACKUP/runtime/bin/$unit"
  printf '%s\t%s\n' "$unit" "$binary" >> "$BACKUP/runtime/binary-paths.tsv"
  systemctl cat "$unit" > "$BACKUP/runtime/units/$unit.unit.txt"
  systemctl show "$unit" -p Id -p ActiveState -p SubState -p MainPID -p NRestarts -p FragmentPath -p DropInPaths > "$BACKUP/runtime/units/$unit.state.txt"
  for path in "/etc/systemd/system/$unit.service" "/etc/systemd/system/$unit.service.d"; do
    if [[ -e $path ]]; then cp -a --parents -- "$path" "$BACKUP/runtime"; fi
  done
done
for path in /root/cham-server.env /root/cham-allow.txt; do
  if [[ -f $path ]]; then cp -a --parents -- "$path" "$BACKUP/runtime"; fi
done
ip -j route show table all > "$BACKUP/runtime/routes-v4.json"
ip -j -6 route show table all > "$BACKUP/runtime/routes-v6.json"
ip -j addr > "$BACKUP/runtime/addresses.json"
ss -lntup > "$BACKUP/runtime/listeners.txt"
(cd "$BACKUP/runtime" && sha256sum bin/* > SHA256SUMS && sha256sum -c SHA256SUMS)
tar -czf "$BACKUP/runtime-before.tar.gz" -C "$BACKUP" runtime
tar -tzf "$BACKUP/runtime-before.tar.gz" >/dev/null
(cd "$BACKUP" && sha256sum source-before.tar.gz runtime-before.tar.gz > SHA256SUMS && sha256sum -c SHA256SUMS)
sha256sum "$ROOT/go.mod" "$ROOT/internal/chameleon/resolver.go" "$ROOT/internal/chameleon/shaper.go" "$ROOT/cmd/chamd/autopilot.go" > "$WORK/results/canonical-before.sha256"
systemctl show cham-server ks-vpn-node chaossync-server -p Id -p MainPID -p NRestarts -p ActiveState > "$WORK/results/services-before.txt"
printf 'WORK=%s\nBACKUP=%s\n' "$WORK" "$BACKUP"
sha256sum "$BACKUP/source-before.tar.gz" "$BACKUP/runtime-before.tar.gz"
