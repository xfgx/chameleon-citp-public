#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
mkdir -p dist/release

command -v go >/dev/null
case "$(go version)" in *'go1.26.3 '*) ;; *) echo 'Go 1.26.3 is required' >&2; exit 1;; esac

gofmt -w internal/chameleon/*.go cmd/cham-server/*.go cmd/chamd/*.go cmd/cham-client/*.go cmd/cham-keygen/*.go tools/citp-sim/*.go tools/ttl-smuggle/*.go
go test ./internal/chameleon ./cmd/cham-server
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o dist/release/cham-server-linux-amd64 ./cmd/cham-server
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o dist/release/cham-server-windows-amd64.exe ./cmd/cham-server
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o dist/release/chamd-windows-amd64.exe ./cmd/chamd
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o dist/release/cham-client-windows-amd64.exe ./cmd/cham-client
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o dist/release/cham-client-linux-amd64 ./cmd/cham-client
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o dist/release/cham-keygen-windows-amd64.exe ./cmd/cham-keygen
# CITP v3.0: CPI-Scatter/ZPL4 симулятор и Sub-Horizon TTL smuggler
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o dist/release/citp-sim-linux-amd64 ./tools/citp-sim
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o dist/release/citp-sim-windows-amd64.exe ./tools/citp-sim
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o dist/release/ttl-smuggle-linux-amd64 ./tools/ttl-smuggle
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o dist/release/ttl-smuggle-windows-amd64.exe ./tools/ttl-smuggle
sha256sum dist/release/cham-server-linux-amd64 dist/release/cham-client-linux-amd64 dist/release/citp-sim-linux-amd64 dist/release/ttl-smuggle-linux-amd64 dist/release/*.exe > dist/release/SHA256SUMS

cat <<'ANDROID'
Android release prerequisites: JDK 17, Android SDK platform 34, build-tools 34.x,
Android NDK, Go 1.26.3, gomobile, and at least 3 GiB free disk.
Then run:
  gomobile init
  gomobile bind -target=android/arm64 -androidapi 23 -o android/app/libs/mobilecore.aar ./mobilecore
  (cd android && gradle --no-daemon assembleDebug)
  cp android/app/build/outputs/apk/debug/app-debug.apk dist/release/ChameleonVPN-debug.apk
ANDROID
