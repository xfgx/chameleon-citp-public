import paramiko
K='/files/VPN/bin/data/ssh_ed25519'; H='/files/VPN/bin/data/known_hosts'
c=paramiko.SSHClient(); c.load_host_keys(H); c.set_missing_host_key_policy(paramiko.RejectPolicy())
c.connect('192.0.2.10',username='root',key_filename=K,timeout=30)
script=r'''#!/bin/bash
set -u
OUT=/root/build/apk-20260919-full
mkdir -p $OUT
exec > $OUT/build.log 2>&1
export HOME=/root GOPATH=/root/go GOMODCACHE=/root/go/pkg/mod GOCACHE=/root/.cache/go-build
export PATH=/usr/local/go/bin:/root/go/bin:/opt/gradle/gradle-8.7/bin:/opt/android-sdk/platform-tools:/usr/bin:/bin
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOFLAGS=-mod=mod GOMAXPROCS=2 GOMEMLIMIT=900MiB
export ANDROID_HOME=/opt/android-sdk ANDROID_SDK_ROOT=/opt/android-sdk
export ANDROID_NDK_HOME=/opt/android-sdk/ndk/26.1.10909125
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
echo "APK_BUILD_START $(date -u +%FT%T%:z)"
free -m | head -2
cd /root/vpn
echo "== backup old aar"
cp -a android/app/libs/mobilecore.aar $OUT/mobilecore.aar.prev 2>/dev/null
echo "== gomobile bind"
gomobile bind -target=android/arm64,android/arm -androidapi 23 -trimpath -o $OUT/mobilecore.aar ./mobilecore
rc=$?; echo "GOMOBILE_RC=$rc"
if [ $rc -ne 0 ]; then echo "APK_ABORT gomobile failed"; exit 1; fi
ls -l $OUT/mobilecore.aar
sha256sum $OUT/mobilecore.aar
cp -f $OUT/mobilecore.aar android/app/libs/mobilecore.aar
echo "== gradle assembleDebug"
cd /root/vpn/android
cat gradle.properties
gradle --no-daemon assembleDebug
rc=$?; echo "APK_GRADLE_RC=$rc"
APK=$(find /root/vpn/android/app/build/outputs/apk/debug -name '*.apk' | head -1)
echo "APK_PATH=$APK"
if [ -z "$APK" ]; then echo "APK_MISSING"; exit 1; fi
cp -f "$APK" /root/dist/ChameleonVPN-debug.apk
ls -l /root/dist/ChameleonVPN-debug.apk
sha256sum /root/dist/ChameleonVPN-debug.apk
/opt/android-sdk/build-tools/*/aapt dump badging /root/dist/ChameleonVPN-debug.apk 2>/dev/null | head -4
unzip -l /root/dist/ChameleonVPN-debug.apk | grep -E "lib/|\.dex" | head -10
echo "APK_OK"
echo "APK_BUILD_DONE $(date -u +%FT%T%:z)"
'''
sf=c.open_sftp()
with sf.open('/root/build/apk-full.sh','w') as f: f.write(script)
sf.chmod('/root/build/apk-full.sh',0o755)
sf.close()
_,o,e=c.exec_command('nohup bash /root/build/apk-full.sh >/dev/null 2>&1 < /dev/null & echo PID $!',timeout=30)
print(o.read().decode(),e.read().decode())
c.close()
