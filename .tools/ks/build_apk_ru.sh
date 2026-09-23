#!/bin/sh
# build_apk_ru.sh — сборка debug-APK ChameleonVPN на RU-ноде.
#
# Почему не "просто gradle assembleDebug":
# у ноды 1967 МБ RAM и НОЛЬ swap, а в репозитории gradle.properties просит
# -Xmx3g. Такая куча не влезает физически: JVM либо не стартует, либо ядро
# зовёт OOM-killer — а он может прибить продовые ks-vpn-node/ks-vpn-exit и
# оборвать рабочий туннель владельца. Поэтому: подкачка как страховка,
# скромная куча, один воркер, Kotlin в том же JVM (без второго демона).
#
# Маркеры для грепа: APK_BUILD_START, SWAP_*, GP_SET, APK_GRADLE_RC=,
# APK_OK, APK_MISSING, APK_BUILD_DONE.

GRADLE=/opt/gradle/gradle-8.7/bin/gradle
PROJ=/root/vpn/android
SDK=/opt/android-sdk
NDKV=26.1.10909125

echo "APK_BUILD_START $(date -Is)"

[ -x "$GRADLE" ] || { echo "APK_NO_GRADLE $GRADLE"; exit 2; }
[ -d "$PROJ" ] || { echo "APK_NO_PROJ $PROJ"; exit 2; }
[ -d "$SDK/platforms/android-34" ] || { echo "APK_NO_PLATFORM"; exit 2; }
[ -f "$PROJ/app/libs/mobilecore.aar" ] || { echo "APK_NO_AAR"; exit 2; }

# --- 1) подкачка: страховка от OOM-килла продовых сервисов ---
if [ "$(swapon --show --noheadings 2>/dev/null | wc -l)" -eq 0 ]; then
	if fallocate -l 4G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=4096 status=none 2>/dev/null; then
		chmod 600 /swapfile
		mkswap /swapfile >/dev/null 2>&1
		if swapon /swapfile 2>/dev/null; then echo "SWAP_ON_4G"; else echo "SWAP_FAILED_ON"; fi
	else
		echo "SWAP_FAILED_ALLOC"
	fi
else
	echo "SWAP_ALREADY"
fi
free -m | sed -n '1,3p'

# --- 2) gradle.properties под реальную память (бэкап один раз) ---
GP="$PROJ/gradle.properties"
if [ -f "$GP" ] && [ ! -f "$GP.orig" ]; then cp -f "$GP" "$GP.orig"; fi
cat > "$GP" <<'EOF'
org.gradle.jvmargs=-Xmx1200m -XX:MaxMetaspaceSize=384m -Dfile.encoding=UTF-8
android.useAndroidX=true
android.nonTransitiveRClass=true
org.gradle.daemon=false
org.gradle.parallel=false
org.gradle.workers.max=1
kotlin.compiler.execution.strategy=in-process
kotlin.incremental=false
EOF
echo "GP_SET"
cat "$GP"

# --- 3) окружение SDK/NDK/JDK ---
export ANDROID_HOME="$SDK"
export ANDROID_SDK_ROOT="$SDK"
export ANDROID_NDK_HOME="$SDK/ndk/$NDKV"
export GRADLE_USER_HOME=/root/.gradle
if [ -z "$JAVA_HOME" ] || [ ! -d "$JAVA_HOME" ]; then
	JC=$(command -v javac 2>/dev/null)
	if [ -n "$JC" ]; then
		JAVA_HOME=$(dirname "$(dirname "$(readlink -f "$JC")")")
		export JAVA_HOME
	fi
fi
echo "JAVA_HOME=$JAVA_HOME"

# --- 4) сборка ---
cd "$PROJ" || { echo "APK_NO_CD"; exit 2; }
nice -n 10 "$GRADLE" assembleDebug --console=plain --no-daemon --stacktrace
rc=$?
echo "APK_GRADLE_RC=$rc"

APK="$PROJ/app/build/outputs/apk/debug/app-debug.apk"
if [ -f "$APK" ]; then
	mkdir -p /root/dist
	cp -f "$APK" /root/dist/ChameleonVPN-debug.apk
	ls -la /root/dist/ChameleonVPN-debug.apk
	sha256sum /root/dist/ChameleonVPN-debug.apk
	"$SDK/build-tools/34.0.0/aapt2" dump badging /root/dist/ChameleonVPN-debug.apk 2>/dev/null | sed -n '1,4p'
	echo "APK_OK"
else
	echo "APK_MISSING"
	find "$PROJ/app/build/outputs" -type f 2>/dev/null | head -20
fi
echo "APK_BUILD_DONE $(date -Is)"
