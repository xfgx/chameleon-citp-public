import paramiko
K='/files/VPN/bin/data/ssh_ed25519'; H='/files/VPN/bin/data/known_hosts'
c=paramiko.SSHClient(); c.load_host_keys(H); c.set_missing_host_key_policy(paramiko.RejectPolicy())
c.connect('192.0.2.10',username='root',key_filename=K,timeout=30)
script=r'''#!/bin/bash
set -u
NAME=ks-windows-client-20260919-full
OUT=/root/dist/$NAME
LOG=/root/build/windows-20260919-full.log
exec > $LOG 2>&1
export HOME=/root GOPATH=/root/go GOMODCACHE=/root/go/pkg/mod GOCACHE=/root/.cache/go-build
export PATH=/usr/local/go/bin:/usr/bin:/bin GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
export GOOS=windows GOARCH=amd64 CGO_ENABLED=0 GOMAXPROCS=1 GOFLAGS='-mod=mod -p=1'
echo "WIN_BUILD_START $(date -u +%FT%T%:z)"
rm -rf $OUT $OUT.tar.gz
mkdir -p $OUT
cd /root/vpn
for pair in "ks-vpn-windows-amd64.exe ./cmd/ks-vpn" "chamd-windows-amd64.exe ./cmd/chamd" "chaossync-selftest-windows-amd64.exe ./cmd/chaossync-selftest"; do
  set -- $pair
  echo "== build $1"
  go build -trimpath -buildvcs=false -ldflags='-s -w' -o "$OUT/$1" "$2"; echo "rc_$1=$?"
done
echo "== research tests"
go test -c -trimpath -buildvcs=false -o "$OUT/ks-research-tests-windows-amd64.exe" ./internal/chaossync; echo "rc_tests=$?"
echo "== packaging"
cp -a packaging/windows/. "$OUT/"
cp /root/dist/ks-windows-client-20260904b/wintun.dll "$OUT/wintun.dll"
mkdir -p "$OUT/docs"; cp docs/KS-RESEARCH.md "$OUT/docs/" 2>/dev/null
rm -f "$OUT/SHA256SUMS" "$OUT/BUILD-PENDING.txt"
cd "$OUT"
find . -type f -not -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
sha256sum -c SHA256SUMS | grep -v ': OK' || echo CHECKSUMS_OK
cd /root/dist
tar -czf $NAME.tar.gz $NAME
tar -tzf $NAME.tar.gz > /dev/null && echo TAR_OK
stat -c '%s %n' /root/dist/$NAME.tar.gz
sha256sum /root/dist/$NAME.tar.gz
find $OUT -maxdepth 2 -type f -printf '%P\t%s\n' | sort
echo "== secret scan"
grep -rIl -E 'BEGIN (OPENSSH|RSA|EC) PRIVATE KEY|private:' $OUT || echo NO_PRIVATE_KEYS
echo "WIN_BUILD_DONE $(date -u +%FT%T%:z)"
'''
sf=c.open_sftp()
with sf.open('/root/build/win-full.sh','w') as f: f.write(script)
sf.chmod('/root/build/win-full.sh',0o755)
sf.close()
ch=c.get_transport().open_session()
ch.exec_command('nohup bash /root/build/win-full.sh >/dev/null 2>&1 < /dev/null & disown; echo LAUNCHED')
import time; time.sleep(3)
print(ch.recv(200).decode(errors='replace'))
c.close()
