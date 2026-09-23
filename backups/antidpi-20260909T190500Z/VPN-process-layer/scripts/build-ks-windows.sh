#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
OUT=${1:?new absolute output directory required}
[[ "$OUT" = /* && ! -e "$OUT" ]] || { echo 'Refusing existing or relative output' >&2; exit 2; }
mkdir -p "$OUT"
cd "$ROOT"
export GOOS=windows GOARCH=amd64 CGO_ENABLED=0 GOPROXY=off GOTOOLCHAIN=local GOMAXPROCS=1
export GOFLAGS='-mod=readonly -p=1'
go build -trimpath -buildvcs=false -ldflags='-s -w' -o "$OUT/ks-vpn-windows-amd64.exe" ./cmd/ks-vpn
go build -trimpath -buildvcs=false -ldflags='-s -w' -o "$OUT/chaossync-selftest-windows-amd64.exe" ./cmd/chaossync-selftest
go test -c -trimpath -buildvcs=false -o "$OUT/ks-research-tests-windows-amd64.exe" ./internal/chaossync
cp -a packaging/windows/. "$OUT/"
cp bin/wintun.dll "$OUT/wintun.dll"
mkdir -p "$OUT/docs"
cp docs/KS-RESEARCH.md "$OUT/docs/"
printf '%s\n' 'Build completed; release validation and final SHA256SUMS are separate required steps.' > "$OUT/BUILD-PENDING.txt"
