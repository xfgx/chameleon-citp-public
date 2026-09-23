@echo off
cd /d %~dp0
echo CDT VPN client: SOCKS5 на 127.0.0.1:1080 -> нода 192.0.2.10 (блок 20000-20047)
cdt-socks-windows-amd64.exe -peer 192.0.2.10 -keyfile data\cdt.key
pause
