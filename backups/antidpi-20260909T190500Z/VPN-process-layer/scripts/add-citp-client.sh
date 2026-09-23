#!/bin/sh
set -eu
KEY=${1:-}
ALLOW=${ALLOWFILE:-/root/cham-allow.txt}
case "$KEY" in
  *[!A-Za-z0-9_-]*|'') echo "Usage: $0 <X25519-public-key>" >&2; exit 2 ;;
esac
[ ${#KEY} -eq 43 ] || { echo "Public key must be 43 base64url characters" >&2; exit 2; }
touch "$ALLOW"
chmod 600 "$ALLOW"
if grep -Fxq "$KEY" "$ALLOW"; then
  echo "Client already allowed"
else
  cp -a "$ALLOW" "$ALLOW.bak.$(date -u +%Y%m%dT%H%M%SZ)"
  printf '%s\n' "$KEY" >> "$ALLOW"
  sort -u "$ALLOW" -o "$ALLOW"
  echo "Client key added"
fi
systemctl restart cham-server.service
systemctl is-active --quiet cham-server.service
echo "cham-server active"
