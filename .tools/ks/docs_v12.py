import io, re, sys

P = "/files/VPN/docs/KS.md"
s = io.open(P, encoding="utf-8").read()
heads = [l for l in s.split("\n") if l.startswith("#")]
print("---HEADINGS---")
for h in heads[-6:]:
    print(h)

if "Андроид-клиент v12" in s:
    print("DOC_ALREADY")
    sys.exit(0)

nums = [int(m.group(1)) for m in (re.match(r"^#+\s*(\d+)[.)]", h) for h in [x]) if m for x in [h]] if False else []
last = 0
for h in heads:
    m = re.match(r"^(#+)\s*(\d+)[.)]?\s", h)
    if m:
        last = max(last, int(m.group(2)))
        lvl = m.group(1)
lvl = lvl if last else "##"
n = last + 1

sec = []
sec.append("")
sec.append(lvl + " " + str(n) + ". Андроид-клиент v12: честное отключение и вкладка «Инструкция»")
sec.append("")
sec.append("**Симптом.** Нажатие «Отключить» рвало связь с нодой, но не опускало VPN")
sec.append("на уровне устройства: значок туннеля оставался гореть.")
sec.append("")
sec.append("**Причина (доказана кодом).** `stopKS()` отменял только контекст. Kotlin отдаёт")
sec.append("ядру `ParcelFileDescriptor.dup(...).detachFd()`, то есть второй дескриптор того же tun.")
sec.append("Android держит VPN-интерфейс живым, пока открыт хотя бы один fd, а читающая")
sec.append("горутина висела в блокирующем `syscall.Read` и проверяла отмену только *перед*")
sec.append("чтением — без входящего пакета она не выходила никогда.")
sec.append("")
sec.append("**Исправление в `mobilecore/ks.go`:**")
sec.append("")
sec.append("- `syscall.SetNonblock(tunFd)` + `os.NewFile` — чтение/запись через runtime-поллер,")
sec.append("  поэтому `Close()` гарантированно будит читателя (задержка не растёт).")
sec.append("- новые `ksTunFile *os.File` и `ksSock *net.UDPConn`; `stopKS()` закрывает оба")
sec.append("  после отмены контекста и сбрасывает `ksLastRx`.")
sec.append("- читатель различает `os.ErrClosed`/`EBADF` (выход) и `EAGAIN` (пауза 5 мс),")
sec.append("  так что спина на закрытом дескрипторе больше нет.")
sec.append("")
sec.append("**`ChamVpnService.kt`:** порядок остановки `Mobilecore.stop()` → `tun.close()` →")
sec.append("`stopForeground(STOP_FOREGROUND_REMOVE)` → `stopSelf()`; добавлен публичный")
sec.append("`lifecycle: VpnLifecycleState` для UI и лог `туннель отпущен, сетевой интерфейс закрыт`.")
sec.append("")
sec.append("**`MainActivity.kt` (правки точечные, новый тёмный дизайн сохранён):**")
sec.append("")
sec.append("- пятая вкладка `TAB_HELP` + `buildHelpPage()` — 8 разделов инструкции на `card()`.")
sec.append("- навигация вмещает 5 кнопок: у `MaterialButton` сняты inset-отступы и `minWidth`,")
sec.append("  включён autosize 8–11sp, паддинги полосы `2/4/2/6dp`.")
sec.append("- `refreshNav()` больше не зависит от порядка детей — номер вкладки в `tag`;")
sec.append("  активная подсвечивается `cAccentDim`.")
sec.append("- `pollStopped()` опрашивает состояние каждые 250 мс (гейт 6 с) вместо глухой")
sec.append("  паузы 4 с; на время остановки статус «Отключаем…».")
sec.append("")
sec.append(lvl + "# " + str(n) + ".1 Артефакт и верификация")
sec.append("")
sec.append("`/root/dist/ChameleonVPN-debug.apk`, 41 126 658 б, versionCode 5 / 3.1.0,")
sec.append("sha256 `a2b64c198f17fc6a9400401cdc6dffc84ba88a3c36cbda36403e11c93e06fc15`.")
sec.append("Проверено: 4 ABI (`arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64`);")
sec.append("`assets/ks-vpn.key` md5 `59842b0fce06179c653ec151ceafea23` = `/root/build/ks-phone.key`;")
sec.append("новый UI в `classes3.dex` (`buildHelpPage`, `pollStopped`, «Инструкция»);")
sec.append("новое ядро в `lib/arm64-v8a/libgojni.so` (строки `интерфейс отпущен`,")
sec.append("`читатель остановлен`). `gofmt`, `go vet ./mobilecore`, `go build ./mobilecore` — rc=0,")
sec.append("`gomobile bind` rc=0 (AAR 26 929 570 б), Gradle `BUILD SUCCESSFUL in 58s`.")
sec.append("")
sec.append("Откат: рабочий AAR — `/root/build/mobilecore.aar.bak-good`, исходники —")
sec.append("`backups/app-v12-*` и `backups/ui-v12-*` в репозитории.")
sec.append("")
sec.append(lvl + "# " + str(n) + ".2 Мультиклиент (телефон рядом с ПК)")
sec.append("")
sec.append("`ks-vpn-phone.service`: `-tun ksphone0 -tunip 10.99.1.2/24 -listen 51822`,")
sec.append("ключ `ks-phone.key`, masquerade `10.99.1.0/24` на `ks1`/`ens3`,")
sec.append("`ip rule pref 101 iif ksphone0 lookup 100`. На телефоне tun-адрес `10.99.1.1`")
sec.append("(`ownTun` в `ks.go` и `tunAddr` в `ChamVpnService`), пресет `ks-ru` — `:51822`.")
sec.append("Каналы ПК (`:51820`) и телефона независимы и работают одновременно.")
sec.append("")
sec.append("**Предел (честно).** Живого прогона на телефоне у разработчика не было.")
sec.append("Гейт на приёмку: после «Отключить» в журнале должна появиться строка")
sec.append("`KS: tun fd=N закрыт, интерфейс отпущен`, а значок VPN в статус-баре — погаснуть.")
sec.append("")

if not s.endswith("\n"):
    s += "\n"
s += "\n".join(sec)
io.open(P, "w", encoding="utf-8", newline="").write(s)
print("DOC_APPENDED section=" + str(n) + " level=" + lvl)
