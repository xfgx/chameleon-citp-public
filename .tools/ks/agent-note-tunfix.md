
### 2026-09-01T14:05Z — ks-vpn tun_windows.go v2: полевой багфикс блокирующего Read (по логу владельца с Windows-ПК)

- Полевой лог владельца (первый живой запуск архива на Windows 11): Wintun 0.14 поднялся, адаптер создан (с зачисткой осиротевшего), TUN ks0 поднялся с 10.99.0.1/24, UDP :23500 слушал — и процесс завершался сразу: `tun read: No more data is available.`
- Корневая причина (подтверждена по исходникам golang.zx2c4.com/wintun на ноде): `Session.ReceivePacket()` НЕблокирующий — на пустом ring-буфере возвращает `ERROR_NO_MORE_ITEMS` (259; константа есть в x/sys v0.47.0). v1 моего `tun_windows.go` отдавал эту ошибку наверх, где `log.Fatalf` убивал клиента.
- Фикс (tun_windows.go v2): `Read()` блокируется на `session.ReadWaitEvent()` через `windows.WaitForSingleObject(..., INFINITE)` при ERROR_NO_MORE_ITEMS — правильный паттерн wintun; настоящие ошибки по-прежнему фатальны. `Write()` — ретраи до 100×1 мс при переполнении ring передачи, дальше честная ошибка (пакет отброшен, TCP перешлёт).
- Проверка на RU-ноде: gofmt чист, `go vet ./cmd/ks-vpn` чист на linux И windows, пересборка `ks-vpn-windows-amd64.exe` на ноде — ОК.
- Архив перепакован: `/root/dist/ks-windows-client-20260901.tar.gz` — sha256 `995b96e2cb1957aaeb0bcb8ce527744a27c346968a138d2e1eb7ec4b614536c4`, 4 058 445 Б (также внутри: run-ks-vpn.bat с `chcp 65001` — чинит кракозябры эха в cmd). `dist/ks-chaos-20260901/` обновлён тем же exe, SHA256SUMS переписан.
- НЕ СДЕЛАНО (честно): полный живой прогон v2 на Windows-ПК (поднятие + ping 10.99.0.2 + трафик) — следующий запуск за владельцем; ожидаемое поведение: клиент НЕ завершается, счётчики `стадии: tunRd=… sent=… udpRecv=… ingestOK=…` растут в логе.
