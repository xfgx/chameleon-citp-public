@echo off
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File "%~dp0SELFTEST.ps1"
set "RC=%ERRORLEVEL%"
pause
exit /b %RC%
