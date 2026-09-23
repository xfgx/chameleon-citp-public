@echo off
set PATH=G:\android\jdk\bin;G:\android\gradle-8.7\bin;%PATH%;C:\Program Files\Go\bin;G:\go\bin
set GOPATH=G:\go
set GOMODCACHE=G:\go\pkg\mod
set GOCACHE=G:\go\build-cache
set GOFLAGS=-p=1
set ANDROID_HOME=G:\android\sdk
set ANDROID_NDK_HOME=G:\android\sdk\ndk\26.1.10909125
set GRADLE_USER_HOME=G:\android\gradle-home
cd /d G:\VPN\android
call G:\android\gradle-8.7\bin\gradle.bat assembleDebug --console=plain --no-daemon --stacktrace 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo BUILD FAILED
    exit /b 1
)
copy /Y app\build\outputs\apk\debug\app-debug.apk G:\VPN\bin\ChameleonVPN.apk
dir G:\VPN\bin\ChameleonVPN.apk
echo APK-OK