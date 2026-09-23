@echo off
cd /d %~dp0
echo chaossync client -> 192.0.2.10:4500 (60 сек, кадр-проба сквозь ротации эпох)
chaossync-client-windows-amd64.exe -config client.conf
pause
