import paramiko, time
K='/files/VPN/bin/data/ssh_ed25519'; H='/files/VPN/bin/data/known_hosts'
c=paramiko.SSHClient(); c.load_host_keys(H); c.set_missing_host_key_policy(paramiko.RejectPolicy())
c.connect('192.0.2.10',username='root',key_filename=K,timeout=30)
script=r'''#!/bin/bash
set -u
TS=20260919-full
OUT=/root/build/full-rebuild-$TS
mkdir -p $OUT
exec > $OUT/merge.log 2>&1
A=/root/build/vpn-console-20260919-01/src
B=/root/vpn
export HOME=/root GOPATH=/root/go GOMODCACHE=/root/go/pkg/mod GOCACHE=/root/.cache/go-build
export PATH=/usr/local/go/bin:/root/go/bin:/usr/bin:/bin GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOFLAGS=-mod=mod GOMAXPROCS=2 GOMEMLIMIT=900MiB

echo "== backup working tree"
tar --exclude=android/app/build --exclude=android/.gradle --exclude=bundle --exclude=bundle-cdt --exclude=bundle-cdt-socks -czf /root/build/backup-vpn-tree-$TS.tgz -C /root vpn 2>/dev/null
ls -lh /root/build/backup-vpn-tree-$TS.tgz

echo "== sync archive sources into working tree (keep gradle.properties, go.mod)"
cd $A
find . -type f \( -name '*.go' -o -name '*.kt' -o -name '*.gradle' -o -name '*.ps1' -o -name '*.cmd' -o -name '*.sh' -o -name 'AndroidManifest.xml' -o -name '*.md' -o -name '*.txt' -o -name '*.html' -o -name '*.css' -o -name '*.js' \) \
  | grep -v "/build/" | grep -v "/\.gradle/" | sed 's|^\./||' | sort > $OUT/synclist
wc -l < $OUT/synclist
while read f; do
  mkdir -p "$B/$(dirname $f)"
  if ! cmp -s "$A/$f" "$B/$f"; then echo "SYNC $f"; cp -a "$A/$f" "$B/$f"; fi
done < $OUT/synclist

echo "== gofmt"
cd $B
gofmt -l cmd internal mobilecore 2>/dev/null
echo "== go build all"
go build ./... ; echo "build_all_rc=$?"
echo "== go vet"
go vet ./cmd/... ./internal/... ; echo "vet_rc=$?"
echo "== go test"
go test ./internal/chameleon ./cmd/chamd ./cmd/cham-server ./cmd/ks-admin ./mobilecore -count=1 -timeout=12m ; echo "test_rc=$?"

echo "== build binaries"
go build -trimpath -ldflags "-s -w" -o $OUT/cham-server ./cmd/cham-server ; echo "cham_rc=$?"
go build -trimpath -ldflags "-s -w" -o $OUT/chamd ./cmd/chamd ; echo "chamd_rc=$?"
go build -trimpath -ldflags "-s -w" -o $OUT/ks-hub ./cmd/ks-hub ; echo "kshub_rc=$?"
go build -trimpath -o $OUT/ks-admin ./cmd/ks-admin ; echo "admin_rc=$?"
ls -l $OUT
sha256sum $OUT/cham-server $OUT/chamd $OUT/ks-hub $OUT/ks-admin
echo "MERGE_DONE"
'''
sf=c.open_sftp()
with sf.open('/root/build/full-merge.sh','w') as f: f.write(script)
sf.chmod('/root/build/full-merge.sh',0o755)
sf.close()
_,o,e=c.exec_command('nohup bash /root/build/full-merge.sh >/dev/null 2>&1 < /dev/null & echo PID $!',timeout=30)
print(o.read().decode(),e.read().decode())
c.close()
