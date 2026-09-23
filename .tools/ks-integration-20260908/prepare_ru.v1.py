import pathlib,shutil,json,hashlib,os
r=pathlib.Path('/root/build/ks-integration-20260908');r.mkdir(mode=448)
src=pathlib.Path('/root/vpn');dst=r/'project';dst.mkdir()
for sub in ['internal','cmd/ks-vpn','cmd/chaossync-selftest']:
 for p in (src/sub).rglob('*.go'):
  if p.is_symlink():raise RuntimeError('symlink')
  q=dst/p.relative_to(src);q.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,q)
for sub in ['packaging/windows','research/ks-r2-20260908']:
 shutil.copytree(src/sub,dst/sub)
for n in ['go.mod','go.sum','bin/wintun.dll','scripts/build-ks-windows.sh','internal/chaossync/testdata/ks_r1_fields.json','docs/KS-RESEARCH.md']:
 q=dst/n;q.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src/n,q)
with __import__('tarfile').open('/root/backups/ks-integration-20260908-01/before.tar.gz') as t:
 (r/'map.before.go.txt').write_bytes(t.extractfile('internal/chaossync/map.go').read())
(r/'check_tokens.go').write_text('''package main
import("go/scanner";"go/token";"os";"fmt";"reflect")
func scan(p string) []string {b,e:=os.ReadFile(p);if e!=nil {panic(e)};f:=token.NewFileSet().AddFile(p,-1,len(b));var s scanner.Scanner;s.Init(f,b,nil,0);var out []string;for {_,t,l:=s.Scan();if t==token.EOF {break};out=append(out,fmt.Sprint(t,"|",l))};if s.ErrorCount>0 {panic("scanner errors")};return out}
func main(){if !reflect.DeepEqual(scan(os.Getenv("MAP_BEFORE")),scan(os.Getenv("MAP_AFTER"))) {panic("code token mismatch")};fmt.Println("PASS identical Go tokens excluding comments")}
''')
(r/'run_build.sh').write_text('''#!/bin/bash
set -euo pipefail
R=/root/build/ks-integration-20260908
export PATH=/usr/local/go/bin:/usr/bin:/bin HOME=/root GOPATH=/root/go GOMODCACHE=/root/go/pkg/mod GOCACHE=$R/go-cache GOMAXPROCS=1 GOPROXY=off GOTOOLCHAIN=local CGO_ENABLED=0
export GOFLAGS='-mod=readonly -p=1'
cd "$R/project"
date -u +%FT%TZ > "$R/build-started.txt"
go version
go env GOOS GOARCH GOVERSION CGO_ENABLED GOPROXY GOTOOLCHAIN
gofmt -w internal/chaossync/ks_research_regression_test.go research/ks-r2-20260908/channel_lab/main.go
MAP_BEFORE=$R/map.before.go.txt MAP_AFTER=$R/project/internal/chaossync/map.go go run "$R/check_tokens.go" | tee "$R/code-token-check.log"
go test -count=1 ./internal/chaossync -run 'TestKSResearch|TestKsGoldenVector' -v -timeout 180s | tee "$R/native-regression.log"
go test -count=1 ./cmd/ks-vpn -run '^TestLoopGuardDrop$' -v -timeout 60s | tee "$R/loopguard.log"
go run ./cmd/chaossync-selftest | tee "$R/expected-vectors.txt"
go build -trimpath -buildvcs=false -o "$R/channel-lab" ./research/ks-r2-20260908/channel_lab
bash scripts/build-ks-windows.sh "$R/windows-bundle"
cp "$R/expected-vectors.txt" "$R/windows-bundle/expected-vectors.txt"
file "$R/windows-bundle/"*.exe "$R/windows-bundle/wintun.dll" | tee "$R/pe-check.log"
date -u +%FT%TZ > "$R/build-completed.txt"
echo BUILD_PASS
''')
(r/'run_r2.sh').write_text('''#!/bin/bash
set -euo pipefail
R=/root/build/ks-integration-20260908
"$R/channel-lab" -fields "$R/project/internal/chaossync/testdata/ks_r1_fields.json" -out "$R/r2-results"
date -u +%FT%TZ > "$R/r2-completed.txt"
''')
(r/'run_wine.sh').write_text('''#!/bin/bash
set -euo pipefail
R=/root/build/ks-integration-20260908
export HOME=$R/wine-home WINEPREFIX=$R/wine-prefix WINEDEBUG=-all
mkdir -p "$HOME"
cd "$R/windows-bundle"
timeout 120 wine chaossync-selftest-windows-amd64.exe > "$R/wine-vectors.raw.txt" 2> "$R/wine-init.log"
tr -d '\\r' < "$R/wine-vectors.raw.txt" > "$R/wine-vectors.txt"
diff -u "$R/expected-vectors.txt" "$R/wine-vectors.txt"
timeout 180 wine ks-research-tests-windows-amd64.exe -test.run '^(TestKSResearchLengthContract|TestKSResearchScheduleRegression|TestKsGoldenVector)$' -test.v -test.timeout 180s > "$R/wine-tests.log" 2>&1
date -u +%FT%TZ > "$R/wine-completed.txt"
echo WINE_PASS
''')
manifest={str(p.relative_to(dst)):hashlib.sha256(p.read_bytes()).hexdigest() for p in dst.rglob('*') if p.is_file()}
(r/'source-before-format.json').write_text(json.dumps(manifest,indent=2))
print('ISOLATED PROJECT CREATED',len(manifest),'files; no credential directories copied')
