#!/bin/bash
set -eu
umask 077
cd /root/build/ks-r1-20260908
trap 'rc=$?; echo RUN_RC=$rc > /root/build/ks-r1-20260908/go_completed.txt; date -u +%FT%TZ >> /root/build/ks-r1-20260908/go_completed.txt' EXIT
export PATH=/usr/local/go/bin:/usr/bin:/bin
export HOME=/root GOPATH=/root/go GOMODCACHE=/root/go/pkg/mod
export GOMAXPROCS=1 GOPROXY=off GOTOOLCHAIN=local
export GOCACHE=/root/build/ks-r1-20260908/go-cache
{ hostname; date -u +%FT%TZ; go version; sha256sum project/internal/chaossync/ks.go project/internal/chaossync/ks_r1_length_test.go; } > go_environment.txt
cd project
KS_R1_LENGTH_CSV=/root/build/ks-r1-20260908/go_length_cases.csv go test -p=1 -run '^(TestKsGoldenVector|TestKsR1LengthContract)$' -count=1 -v ./internal/chaossync > ../go_test.log 2>&1
