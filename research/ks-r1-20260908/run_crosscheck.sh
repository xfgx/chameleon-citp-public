#!/bin/bash
set -eu
cd /root/build/ks-r1-20260908
trap 'rc=$?; echo RUN_RC=$rc > /root/build/ks-r1-20260908/crosscheck_completed.txt' EXIT
export HOME=/root GOPATH=/root/go GOMODCACHE=/root/go/pkg/mod GOCACHE=/root/build/ks-r1-20260908/go-cache
export GOMAXPROCS=1 GOPROXY=off GOTOOLCHAIN=local OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1
cd project
KS_R1_DIR=/root/build/ks-r1-20260908 /usr/local/go/bin/go test -p=1 -run '^TestKsR1KernelFixture$' -count=1 -v ./internal/chaossync > ../kernel_go.log 2>&1
cd ..
python3 verify_kernel.py > kernel_verify.log 2>&1
