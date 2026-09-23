@echo off
chcp 65001 >nul
cd /d %~dp0
echo KS-VPN client v3: TUN 10.99.0.1 -^> нода 192.0.2.10:51820 (нужны права администратора; маршруты настроятся сами, по Ctrl+C - снимутся)
ks-vpn-windows-amd64.exe -tunip 10.99.0.1/24 -peerhost 192.0.2.10 -peerport 51820 -listen 23500 -keyfile data\ks-vpn.key -fulltun
pause
