// ks-exit-setup — самодостаточный установщик зарубежного выхода (второе плечо).
//
// Запускать НА ЗАРУБЕЖНОЙ НОДЕ от root. Внутри уже лежат: бинарь ks-vpn
// (linux/amd64, статик) и мастер-ключ второго плеча.
//
// Роль: инициатор. Звонит САМ на RU:51821, поэтому входящий порт и публичный
// IP зарубежной ноде НЕ НУЖНЫ — работает из-за NAT.
//
// Диагностические принципы (исправлено после первого боевого запуска):
//   1. NAT применяется ИНЛАЙН и весь его вывод печатается на экран ДО
//      запуска сервиса — ошибка видна сразу, а не только в журнале.
//   2. Если сервис не встал — установщик сам печатает systemctl status и
//      journalctl. Не заставлять человека идти за логом вручную.
//   3. Фатально только то, без чего нет выхода (masquerade). Второстепенное
//      (rp_filter, forward-accept) — предупреждение, а не смерть сервиса.
package main

import (
	_ "embed"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

//go:embed assets/ks-vpn
var ksVPNBin []byte

//go:embed assets/ks-hop2.key
var hop2Key []byte

const (
	binPath    = "/usr/local/bin/ks-vpn"
	keyDir     = "/etc/ks-vpn"
	keyPath    = "/etc/ks-vpn/ks-hop2.key"
	natPath    = "/usr/local/sbin/ks-exit-nat.sh"
	unitPath   = "/etc/systemd/system/ks-vpn-exit.service"
	sysctlPath = "/etc/sysctl.d/99-ks-exit.conf"
	tunNet     = "10.98.0.0/24"
	unitName   = "ks-vpn-exit"
)

func main() {
	ruHost := flag.String("ruhost", "192.0.2.10", "публичный IP RU-ноды")
	ruPort := flag.Int("ruport", 51821, "UDP-порт второго плеча на RU")
	tunIP := flag.String("tunip", "10.98.0.2/24", "мой туннельный IP/CIDR")
	peerTun := flag.String("peertunip", "10.98.0.1", "туннельный IP RU-ноды")
	tunName := flag.String("tun", "ks0", "имя TUN")
	wanFlag := flag.String("wan", "", "WAN-интерфейс (пусто = определить самому)")
	rotT := flag.Int("T", 8, "период ротации эпох, сек (ОБЯЗАТЕЛЬНО как на RU)")
	wait := flag.Int("wait", 45, "сколько секунд ждать живого канала при проверке")
	uninstall := flag.Bool("uninstall", false, "снять всё: сервис, unit, NAT, ключ")
	statusOnly := flag.Bool("status", false, "только показать состояние")
	diagOnly := flag.Bool("diag", false, "собрать полную диагностику и выйти")
	flag.Parse()

	if os.Geteuid() != 0 {
		die("нужен root: sudo %s", os.Args[0])
	}

	if *diagOnly {
		showDiag(*tunName)
		return
	}
	if *statusOnly {
		showStatus()
		return
	}
	if *uninstall {
		doUninstall()
		return
	}

	fmt.Println("=== ks-exit-setup: зарубежный выход второго плеча ===")

	// 1. TUN
	if err := ensureTUN(); err != nil {
		die("fail-closed: /dev/net/tun недоступен: %v\n"+
			"Без TUN выходной узел работать не может. Нужны CAP_NET_ADMIN и устройство tun\n"+
			"(в Docker: --cap-add NET_ADMIN --device /dev/net/tun).", err)
	}
	fmt.Println("[ok] /dev/net/tun доступен")

	// 2. WAN
	wan := *wanFlag
	if wan == "" {
		var err error
		wan, err = detectWAN()
		if err != nil {
			die("не смог определить WAN-интерфейс: %v (задай -wan вручную)", err)
		}
	}
	if wan == *tunName {
		die("WAN-интерфейс совпал с именем TUN (%s) — это приведёт к петле", wan)
	}
	fmt.Printf("[ok] WAN-интерфейс: %s\n", wan)

	switch {
	case have("nft"):
		fmt.Println("[ok] NAT будет через: nft")
	case have("iptables"):
		fmt.Println("[ok] NAT будет через: iptables")
	default:
		die("fail-closed: на хосте нет ни nft, ни iptables — NAT поставить нечем")
	}

	// 3. раскладка файлов
	//
	// Сначала глушим сервис: иначе запись поверх работающего бинарника
	// даёт ETXTBSY (text file busy). Ошибку игнорируем — при первой
	// установке unit'а ещё нет.
	if out, err := exec.Command("systemctl", "stop", unitName).CombinedOutput(); err == nil {
		fmt.Printf("[ok] прежний %s остановлен на время обновления\n", unitName)
	} else {
		_ = out
	}
	// Атомарная замена через rename работает даже если старый
	// файл всё ещё исполняется: инода отвязывается, а не переписывается.
	mustWriteAtomic(binPath, ksVPNBin, 0o755)
	mustMkdir(keyDir, 0o700)
	mustWrite(keyPath, hop2Key, 0o600)
	mustMkdir("/usr/local/sbin", 0o755)
	mustWrite(natPath, []byte(natScript(*tunName)), 0o755)
	mustWrite(sysctlPath, []byte("net.ipv4.ip_forward=1\n"), 0o644)
	fmt.Printf("[ok] ks-vpn -> %s (%d байт)\n", binPath, len(ksVPNBin))
	fmt.Printf("[ok] ключ -> %s (0600)\n", keyPath)
	fmt.Printf("[ok] NAT-скрипт -> %s\n", natPath)

	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o644); err != nil {
		fmt.Printf("[warn] ip_forward сейчас не выставился: %v\n", err)
	} else {
		fmt.Println("[ok] ip_forward=1")
	}

	// 4. NAT ПРИМЕНЯЕМ СЕЙЧАС и показываем весь вывод.
	// Раньше это делалось только в ExecStartPre, и ошибка была не видна.
	fmt.Println("--- применяю NAT (инлайн, вывод как есть) ---")
	natOut, natErr := exec.Command("/bin/sh", natPath, wan).CombinedOutput()
	if s := strings.TrimSpace(string(natOut)); s != "" {
		fmt.Println(s)
	}
	if natErr != nil {
		fmt.Println("--- диагностика файрволла ---")
		showDiag(*tunName)
		die("NAT не применился (%v). Сервис НЕ запущен.\n"+
			"Без masquerade выхода в Интернет не будет, поэтому останавливаюсь здесь.", natErr)
	}
	fmt.Println("[ok] NAT применён")

	// 5. unit
	unit := fmt.Sprintf(`[Unit]
Description=Chameleon KS-VPN — foreign exit node (hop2 initiator to RU)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=-/bin/sh %s %s
ExecStart=%s -keyfile %s -tun %s -tunip %s -peerhost %s -peerport %d -listen %d -peertunip %s -outdir x2r -indir r2x -T %d
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`, natPath, wan, binPath, keyPath, *tunName, *tunIP, *ruHost, *ruPort, *ruPort, *peerTun, *rotT)
	mustWrite(unitPath, []byte(unit), 0o644)
	fmt.Printf("[ok] unit -> %s\n", unitPath)

	// 6. автозапуск
	mustRun("systemctl", "daemon-reload")
	mustRun("systemctl", "enable", unitName)
	if out, err := exec.Command("systemctl", "restart", unitName).CombinedOutput(); err != nil {
		fmt.Printf("\nСЕРВИС НЕ ЗАПУСТИЛСЯ: %v\n%s\n", err, strings.TrimSpace(string(out)))
		dumpServiceFailure(*tunName)
		os.Exit(1)
	}
	fmt.Println("[ok] сервис включён в автозапуск и запущен")

	// 7. живая проверка
	fmt.Printf("\n=== проверка канала до RU (до %dс) ===\n", *wait)
	ok, last := waitAlive(*wait)
	fmt.Println("--- последние строки лога ---")
	fmt.Println(last)
	if !ok {
		fmt.Println("\nRESULT: FAIL — валидных датаграмм от RU не пришло.")
		dumpServiceFailure(*tunName)
		fmt.Println("Проверь по порядку:")
		fmt.Printf("  1) исходящий UDP на %s:%d не заблокирован у хостера;\n", *ruHost, *ruPort)
		fmt.Println("  2) на RU запущен ks-vpn-exit;")
		fmt.Println("  3) ключи совпадают (sha256sum /etc/ks-vpn/ks-hop2.key);")
		fmt.Println("  4) -T одинаков на обеих сторонах;")
		fmt.Println("  5) часы расходятся не больше пары секунд (timedatectl).")
		os.Exit(1)
	}
	fmt.Println("\nRESULT: PASS — второе плечо живое, RU отвечает.")
	fmt.Println("Теперь НА RU-НОДЕ выполни: bash /root/build/ks-exit-on.sh")
	fmt.Println("После этого с Windows-ПК: curl.exe --noproxy \"*\" https://api.ipify.org")
}

// natScript — идемпотентный NAT+forward для nft или iptables.
//
// Сознательно БЕЗ "set -e": раньше любой второстепенный шаг (например
// forward-правило с ct state на ядре без conntrack) ронял всю службу.
// Фатальным считается только отсутствие masquerade — без него нет выхода.
func natScript(tun string) string {
	return `#!/bin/sh
# ks-exit-nat.sh <wan-iface> — NAT для ` + tunNet + ` и forward между ` + tun + ` и WAN.
#
# История двух реальных дефектов, найденных в поле (v1..v4):
#   1. Цепочка называлась "fwd", а fwd — КЛЮЧЕВОЕ СЛОВО nft
#      (fwd to <dev>). nft отвергал синтаксис, цепочка НИКОГДА не
#      создавалась. Здесь она называется ksfwd.
#   2. Docker держит в ip filter FORWARD policy drop. Своя nft-таблица с
#      policy accept ЭТОГО НЕ ПЕРЕОПРЕДЕЛЯЕТ: drop в любой таблице на
#      hook forward выигрывает. Разрешать надо в DOCKER-USER — это
#      официальная точка расширения Docker, она не теряется при его
#      рестарте и обрабатывается ДО DOCKER-FORWARD.
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:/usr/bin:/bin
WAN="$1"
TUN="` + tun + `"
NET="` + tunNet + `"
warn() { echo "ks-exit-nat: WARN: $*" >&2; }
# run печатает НАСТОЯЩИЙ текст ошибки, а не глотает его в /dev/null.
run() {
	out=$("$@" 2>&1); rc=$?
	if [ $rc -ne 0 ]; then warn "$* -> rc=$rc: $out"; fi
	return $rc
}
if [ -z "$WAN" ]; then echo "ks-exit-nat: FATAL: не задан WAN-интерфейс" >&2; exit 1; fi

echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || warn "не смог выставить ip_forward"
# loose rp_filter: пути в каскаде асимметричные.
# На момент ExecStartPre интерфейса $TUN ещё нет — это нормально.
for f in all "$TUN"; do
	p=/proc/sys/net/ipv4/conf/$f/rp_filter
	if [ -w "$p" ]; then
		echo 2 > "$p" 2>/dev/null || warn "rp_filter $f"
	fi
done

# ---------- 1. MASQUERADE (единственный фатальный шаг) ----------
MASQ_OK=0
if command -v nft >/dev/null 2>&1; then
	nft add table ip ksx_nat 2>/dev/null
	nft add chain ip ksx_nat post '{ type nat hook postrouting priority srcnat; }' 2>/dev/null
	nft flush chain ip ksx_nat post 2>/dev/null
	if run nft add rule ip ksx_nat post ip saddr $NET oifname "$WAN" counter masquerade; then
		MASQ_OK=1
	fi
fi
if [ $MASQ_OK -eq 0 ] && command -v iptables >/dev/null 2>&1; then
	if iptables -t nat -C POSTROUTING -s $NET -o "$WAN" -j MASQUERADE 2>/dev/null; then
		MASQ_OK=1
	elif run iptables -t nat -A POSTROUTING -s $NET -o "$WAN" -j MASQUERADE; then
		MASQ_OK=1
	fi
fi
if [ $MASQ_OK -eq 0 ]; then
	echo "ks-exit-nat: FATAL: не смог поставить masquerade ($NET -> $WAN)" >&2
	exit 1
fi

# ---------- 2. FORWARD (best-effort, но без него трафика не будет) ----------
FWD_OK=0
FWD_WHERE=""
if command -v iptables >/dev/null 2>&1; then
	# 2a. Если есть Docker — его же точка расширения.
	if iptables -L DOCKER-USER -n >/dev/null 2>&1; then
		iptables -C DOCKER-USER -i "$TUN" -o "$WAN" -j ACCEPT 2>/dev/null \
			|| run iptables -I DOCKER-USER -i "$TUN" -o "$WAN" -j ACCEPT
		iptables -C DOCKER-USER -i "$WAN" -o "$TUN" -j ACCEPT 2>/dev/null \
			|| run iptables -I DOCKER-USER -i "$WAN" -o "$TUN" -j ACCEPT
		if iptables -C DOCKER-USER -i "$TUN" -o "$WAN" -j ACCEPT 2>/dev/null; then
			FWD_OK=1
			FWD_WHERE="DOCKER-USER"
		fi
	fi
	# 2b. Обычный FORWARD.
	if [ $FWD_OK -eq 0 ]; then
		iptables -C FORWARD -i "$TUN" -o "$WAN" -j ACCEPT 2>/dev/null \
			|| run iptables -I FORWARD -i "$TUN" -o "$WAN" -j ACCEPT
		iptables -C FORWARD -i "$WAN" -o "$TUN" -j ACCEPT 2>/dev/null \
			|| run iptables -I FORWARD -i "$WAN" -o "$TUN" -j ACCEPT
		if iptables -C FORWARD -i "$TUN" -o "$WAN" -j ACCEPT 2>/dev/null; then
			FWD_OK=1
			FWD_WHERE="FORWARD"
		fi
	fi
fi
# 2c. Чистый nft-хост без iptables. Поможет только если чужого drop нет.
if [ $FWD_OK -eq 0 ] && command -v nft >/dev/null 2>&1; then
	nft add table ip ksx_fw 2>/dev/null
	nft add chain ip ksx_fw ksfwd '{ type filter hook forward priority 0; }' 2>/dev/null
	nft flush chain ip ksx_fw ksfwd 2>/dev/null
	if run nft add rule ip ksx_fw ksfwd iifname "$TUN" oifname "$WAN" counter accept; then
		FWD_OK=1
		FWD_WHERE="nft ksx_fw"
	fi
	run nft add rule ip ksx_fw ksfwd iifname "$WAN" oifname "$TUN" counter accept
fi

if [ $FWD_OK -eq 0 ]; then
	warn "forward разрешить НЕ УДАЛОСЬ — трафик клиентов не пойдёт в интернет"
else
	echo "ks-exit-nat: forward OK ($TUN <-> $WAN) в $FWD_WHERE"
fi
echo "ks-exit-nat: готов ($NET -> $WAN)"
exit 0
`
}

// dumpServiceFailure — сам показывает всё, что нужно для разбора падения.
func dumpServiceFailure(tun string) {
	fmt.Println("\n================ ДИАГНОСТИКА ПАДЕНИЯ ================")
	show("systemctl", "status", unitName, "--no-pager", "-l")
	show("journalctl", "-xeu", unitName, "-n", "60", "--no-pager")
	showDiag(tun)
	fmt.Println("=========================================================")
	fmt.Println("Пришли этот вывод целиком — в нём видна точная причина.")
}

// showDiag — состояние сети/файрволла/ядра без внешних зависимостей.
func showDiag(tun string) {
	fmt.Println("--- окружение ---")
	for _, f := range []string{
		"/proc/sys/net/ipv4/ip_forward",
		"/proc/sys/net/ipv4/conf/all/rp_filter",
	} {
		if b, err := os.ReadFile(f); err == nil {
			fmt.Printf("%s = %s", f, string(b))
		}
	}
	if _, err := os.Stat("/dev/net/tun"); err == nil {
		fmt.Println("/dev/net/tun = есть")
	} else {
		fmt.Printf("/dev/net/tun = НЕТ (%v)\n", err)
	}
	if b, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(ln, "CapEff") {
				fmt.Println(ln)
			}
		}
	}
	if b, err := os.ReadFile("/proc/net/route"); err == nil {
		fmt.Println("--- /proc/net/route ---")
		fmt.Println(strings.TrimSpace(string(b)))
	}
	if have("ip") {
		show("ip", "-br", "addr", "show")
		show("ip", "link", "show", tun)
	}
	if have("nft") {
		show("nft", "list", "ruleset")
	}
	if have("iptables") {
		show("iptables", "-t", "nat", "-S")
		show("iptables", "-S")
	}
	if have("ss") {
		show("ss", "-lunp")
	}
	if have("timedatectl") {
		show("timedatectl")
	}
	if b, err := os.ReadFile(keyPath); err == nil {
		fmt.Printf("ключ на месте, %d байт (содержимое не печатаю)\n", len(b))
	}
}

func show(name string, args ...string) {
	if !have(name) {
		return
	}
	out, _ := exec.Command(name, args...).CombinedOutput()
	fmt.Printf("--- %s %s ---\n%s\n", name, strings.Join(args, " "), strings.TrimSpace(string(out)))
}

// detectWAN — интерфейс дефолтного маршрута из /proc/net/route (без iproute2).
func detectWAN() (string, error) {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", err
	}
	best, bestMetric := "", 1<<62
	for i, ln := range strings.Split(string(b), "\n") {
		if i == 0 || strings.TrimSpace(ln) == "" {
			continue
		}
		f := strings.Fields(ln)
		if len(f) < 8 {
			continue
		}
		if f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		m, err := strconv.Atoi(f[6])
		if err != nil {
			m = 0
		}
		if m < bestMetric {
			best, bestMetric = f[0], m
		}
	}
	if best == "" {
		return "", fmt.Errorf("дефолтный маршрут не найден")
	}
	return best, nil
}

func ensureTUN() error {
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		_ = os.MkdirAll("/dev/net", 0o755)
		if have("modprobe") {
			_ = exec.Command("modprobe", "tun").Run()
		}
		if _, err2 := os.Stat("/dev/net/tun"); err2 != nil {
			if have("mknod") {
				_ = exec.Command("mknod", "/dev/net/tun", "c", "10", "200").Run()
				_ = os.Chmod("/dev/net/tun", 0o600)
			}
		}
		if _, err3 := os.Stat("/dev/net/tun"); err3 != nil {
			return err3
		}
	}
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return err
	}
	return f.Close()
}

// waitAlive — ждём lastRx отличный от "нет" и ненулевой ingestOK.
// Это значит, что RU принял наш keepalive и ответил — т.е. AEAD и ключи сошлись.
func waitAlive(sec int) (bool, string) {
	deadline := time.Now().Add(time.Duration(sec) * time.Second)
	last := ""
	for time.Now().Before(deadline) {
		out, _ := exec.Command("journalctl", "-u", unitName, "-n", "6", "--no-pager").CombinedOutput()
		last = strings.TrimSpace(string(out))
		for _, ln := range strings.Split(last, "\n") {
			if !strings.Contains(ln, "lastRx=") || !strings.Contains(ln, "ingestOK=") {
				continue
			}
			if !strings.Contains(ln, "lastRx=нет") && !strings.Contains(ln, "ingestOK=0 ") {
				return true, last
			}
		}
		time.Sleep(3 * time.Second)
	}
	return false, last
}

func showStatus() {
	show("systemctl", "is-active", unitName)
	show("systemctl", "is-enabled", unitName)
	show("journalctl", "-u", unitName, "-n", "15", "--no-pager")
	if b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil {
		fmt.Printf("ip_forward=%s", string(b))
	}
	if have("nft") {
		show("nft", "list", "table", "ip", "ksx_nat")
		show("nft", "list", "table", "ip", "ksx_fw")
	}
}

func doUninstall() {
	_ = exec.Command("systemctl", "disable", "--now", unitName).Run()
	for _, p := range []string{unitPath, keyPath, natPath, sysctlPath, binPath} {
		if err := os.Remove(p); err == nil {
			fmt.Printf("удалён %s\n", p)
		}
	}
	_ = os.Remove(keyDir)
	if have("nft") {
		_ = exec.Command("nft", "delete", "table", "ip", "ksx_nat").Run()
		_ = exec.Command("nft", "delete", "table", "ip", "ksx_fw").Run()
	}
	_ = exec.Command("systemctl", "daemon-reload").Run()
	fmt.Println("снято")
}

func have(bin string) bool {
	if _, err := exec.LookPath(bin); err == nil {
		return true
	}
	for _, d := range []string{"/usr/sbin/", "/sbin/", "/usr/bin/", "/bin/", "/usr/local/sbin/", "/usr/local/bin/"} {
		if _, err := os.Stat(d + bin); err == nil {
			return true
		}
	}
	return false
}

func mustRun(name string, args ...string) {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		die("%s %s: %v\n%s", name, strings.Join(args, " "), err, string(out))
	}
}

func mustWrite(path string, data []byte, mode os.FileMode) {
	if err := os.WriteFile(path, data, mode); err != nil {
		die("запись %s: %v", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		die("chmod %s: %v", path, err)
	}
}

// mustWriteAtomic пишет во временный файл рядом и переименовывает его поверх
// целевого. В отличие от os.WriteFile это НЕ даёт ETXTBSY, когда
// старый бинарник в этот момент исполняется.
func mustWriteAtomic(path string, data []byte, mode os.FileMode) {
	tmp := path + ".new"
	_ = os.Remove(tmp)
	if err := os.WriteFile(tmp, data, mode); err != nil {
		die("запись %s: %v", tmp, err)
	}
	if err := os.Chmod(tmp, mode); err != nil {
		die("chmod %s: %v", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		die("замена %s: %v", path, err)
	}
}

func mustMkdir(path string, mode os.FileMode) {
	if err := os.MkdirAll(path, mode); err != nil {
		die("mkdir %s: %v", path, err)
	}
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "ОШИБКА: "+format+"\n", a...)
	os.Exit(1)
}
