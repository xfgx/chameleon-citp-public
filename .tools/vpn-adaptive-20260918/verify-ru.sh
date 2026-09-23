#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ $(hostname) == your-node.example.com ]] || { printf 'Wrong build host\n' >&2; exit 1; }
WORK=/root/build/vpn-adaptive-20260918-01
cd "$WORK/src"
export HOME=/root GOPATH=/root/go GOMODCACHE=/root/go/pkg/mod GOCACHE=/root/.cache/go-build
export PATH=/usr/local/go/bin:/usr/bin:/bin GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
export GOMAXPROCS=2 GOMEMLIMIT=700MiB
[[ $(go version) == 'go version go1.26.3 linux/amd64' ]] || exit 1
changed=(
  internal/chameleon/transport.go internal/chameleon/shaper.go
  internal/chameleon/resolver.go internal/chameleon/mux.go internal/chameleon/cf_theta.go
  internal/chameleon/strategy_survival.go internal/chameleon/strategy_validation.go
  internal/chameleon/semantic_scheduler.go internal/chameleon/resolution_issuance.go
  internal/chameleon/strategy_survival_test.go internal/chameleon/semantic_scheduler_test.go
  internal/chameleon/resolution_canonical_test.go
  cmd/chamd/autopilot.go cmd/chamd/manager.go cmd/chamd/strategy_session.go cmd/chamd/strategy_session_test.go
  cmd/chamd/autopilot_layers_test.go cmd/chamd/autopilot_surrogate_test.go internal/chameleon/chain_test.go
)
case ${1:-} in
  acceptance)
    for phase in unit race vet build; do /bin/bash "$0" "$phase"; done
    ;;
  targeted)
    gofmt -w "${changed[@]}"
    go test ./internal/chameleon ./cmd/chamd -run '^(TestStrategy|TestSemantic|TestResolution|TestThetaFromBoardAndRotate|TestCanaryHandshakeIsNotSurvival|TestChainEndToEnd|TestChainEntryPolicyDNSBinding)' -count=1 -timeout=3m -json > "$WORK/results/targeted.jsonl"
    ;;
  unit)
    go test ./internal/chameleon ./cmd/chamd ./cmd/cham-server -skip '^TestE2EUDPRelay$' -count=1 -timeout=7m -json > "$WORK/results/unit.jsonl"
    ;;
  race)
    CGO_ENABLED=1 go test -race ./internal/chameleon ./cmd/chamd ./cmd/cham-server -skip '^TestE2EUDPRelay$' -count=1 -timeout=9m -json > "$WORK/results/race.jsonl"
    ;;
  vet)
    go vet ./internal/chameleon ./cmd/chamd ./cmd/cham-server ./cmd/cham-client ./mobilecore
    GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./cmd/chamd ./cmd/cham-client
    ;;
  build)
    export CGO_ENABLED=0 GOARCH=amd64
    GOOS=linux go build -trimpath -ldflags='-s -w' -o "$WORK/artifacts/cham-server-linux-amd64" ./cmd/cham-server
    GOOS=linux go build -trimpath -ldflags='-s -w' -o "$WORK/artifacts/cham-client-linux-amd64" ./cmd/cham-client
    GOOS=windows go build -trimpath -ldflags='-s -w' -o "$WORK/artifacts/chamd-windows-amd64.exe" ./cmd/chamd
    GOOS=windows go build -trimpath -ldflags='-s -w' -o "$WORK/artifacts/cham-client-windows-amd64.exe" ./cmd/cham-client
    GOOS=linux go build -trimpath -ldflags='-s -w' -o "$WORK/artifacts/fieldtest-linux-amd64" ./tools/fieldtest
    GOOS=windows go build -trimpath -ldflags='-s -w' -o "$WORK/artifacts/fieldtest-windows-amd64.exe" ./tools/fieldtest
    (cd "$WORK/artifacts" && sha256sum cham-server-linux-amd64 cham-client-linux-amd64 chamd-windows-amd64.exe cham-client-windows-amd64.exe fieldtest-linux-amd64 fieldtest-windows-amd64.exe > SHA256SUMS && sha256sum -c SHA256SUMS)
    ;;
  *) printf 'Expected targeted|unit|race|vet|build\n' >&2; exit 2 ;;
esac
sha256sum "${changed[@]}" > "$WORK/results/source-after.sha256"
printf 'PASS phase=%s host=%s\n' "$1" "$(hostname)"
