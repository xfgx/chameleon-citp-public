package main

// cham-deploy — безопасный деплой cham-server на ноду по SSH.
//
// Аутентификация (в порядке приоритета):
//  1. Ключ: -key / CITP_SSH_KEY; если не заданы, но существует
//     bin/data/ssh_ed25519 — используется он (подписанный доступ агента);
//  2. Пароль: -pass / CITP_SSH_PASS / -passfile. Значения по умолчанию НЕТ:
//     ранее пароль был зашит в исходник и засвечен в операционном выводе —
//     удалён (agent.md, security follow-up), пароль ротирован.
//
// Проверка host key:
//   - -hostkey / CITP_SSH_HOSTKEY — строгий пин SHA256-fingerprint'а;
//   - иначе known_hosts (-knownhosts, по умолчанию bin/data/known_hosts):
//     неизвестный ключ дописывается с печатью fingerprint (TOFU),
//     НЕСОВПАДЕНИЕ известного ключа — фатально. ssh.InsecureIgnoreHostKey
//     больше не используется нигде.
//
// Процедура деплоя (agent.md, правило 10): загрузка во временный путь ->
// сверка SHA-256 -> rollback-копия текущего бинаря -> атомарное переключение
// -> restart -> проверка is-active; при сбое — автоматический откат.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func main() {
	host := flag.String("host", "198.51.100.10:22", "SSH адрес хоста")
	user := flag.String("user", "root", "SSH пользователь")
	pass := flag.String("pass", "", "SSH пароль (лучше: env CITP_SSH_PASS или -passfile)")
	passfile := flag.String("passfile", "", "файл с SSH паролем (0600)")
	keyPath := flag.String("key", "", "путь к приватному SSH-ключу PEM/OpenSSH (env CITP_SSH_KEY; дефолт bin/data/ssh_ed25519 при наличии)")
	hostKeyPin := flag.String("hostkey", "", "пин SHA256 fingerprint host-ключа, напр. SHA256:abc... (env CITP_SSH_HOSTKEY)")
	knownHosts := flag.String("knownhosts", filepath.Join("bin", "data", "known_hosts"), "known_hosts файл (TOFU: неизвестный ключ записывается, конфликт — фатал)")
	localFile := flag.String("file", "bin/cham-server-linux", "локальный файл для загрузки")
	remoteFile := flag.String("remote", "/root/cham-server", "удаленный путь назначения")
	serviceName := flag.String("service", "cham-server", "имя systemd сервиса (пусто = без restart)")
	flag.Parse()

	auth, err := buildAuth(*pass, *passfile, *keyPath)
	if err != nil {
		log.Fatalf("[deploy] аутентификация: %v", err)
	}
	hkcb, err := buildHostKeyCallback(*hostKeyPin, *knownHosts)
	if err != nil {
		log.Fatalf("[deploy] host key: %v", err)
	}

	log.Printf("[deploy] подключение к %s под %s...", *host, *user)
	config := &ssh.ClientConfig{
		User:            *user,
		Auth:            auth,
		HostKeyCallback: hkcb,
		Timeout:         15 * time.Second,
	}
	client, err := ssh.Dial("tcp", *host, config)
	if err != nil {
		log.Fatalf("[deploy] ошибка подключения SSH: %v", err)
	}
	defer client.Close()
	log.Printf("[deploy] SSH подключение успешно установлено")

	// 1. Локальный бинарь + его SHA-256 (этот хэш сверяем на стороне ноды).
	data, err := os.ReadFile(*localFile)
	if err != nil {
		log.Fatalf("[deploy] ошибка чтения локального файла %s: %v", *localFile, err)
	}
	sum := sha256.Sum256(data)
	localSHA := hex.EncodeToString(sum[:])
	log.Printf("[deploy] локальный SHA-256: %s (%d байт)", localSHA, len(data))

	ts := time.Now().UTC().Format("20060102T150405Z")
	remoteTmp := *remoteFile + ".new-" + ts
	backup := *remoteFile + ".backup-" + ts

	// 2. Загрузка во ВРЕМЕННЫЙ путь (боевой бинарь не трогаем до сверки).
	log.Printf("[deploy] отправка на %s ...", remoteTmp)
	upload(client, data, remoteTmp)
	rc, remoteSHA := runCmd(client, "sha256sum "+remoteTmp+" | awk '{print $1}'")
	remoteSHA = strings.TrimSpace(remoteSHA)
	if rc != 0 || remoteSHA != localSHA {
		runCmd(client, "rm -f "+remoteTmp)
		log.Fatalf("[deploy] SHA-256 не сошёлся (local=%s remote=%q) — файл удалён, нода НЕ тронута", localSHA, remoteSHA)
	}
	log.Printf("[deploy] SHA-256 на ноде сошёлся: %s", remoteSHA)

	if *serviceName == "" {
		runCmd(client, fmt.Sprintf("chmod +x %s && mv -f %s %s", remoteTmp, remoteTmp, *remoteFile))
		log.Printf("[deploy] файл установлен без restart (service не задан)")
		return
	}

	// 3. Rollback-копия текущего бинаря, переключение, restart, проверка.
	runCmd(client, fmt.Sprintf("systemctl stop %s || true", *serviceName))
	runCmd(client, fmt.Sprintf("[ -f %s ] && cp -a %s %s || true", *remoteFile, *remoteFile, backup))
	rc, out := runCmd(client, fmt.Sprintf("chmod +x %s && mv -f %s %s && systemctl start %s", remoteTmp, remoteTmp, *remoteFile, *serviceName))
	if rc != 0 {
		rollback(client, *remoteFile, backup, *serviceName)
		log.Fatalf("[deploy] переключение/старт не удались: %s — выполнен откат", out)
	}
	time.Sleep(1500 * time.Millisecond)

	_, status := runCmd(client, fmt.Sprintf("systemctl is-active %s", *serviceName))
	status = strings.TrimSpace(status)
	if status != "active" {
		rollback(client, *remoteFile, backup, *serviceName)
		log.Fatalf("[deploy] сервис не active (%s) — выполнен откат на %s", status, backup)
	}
	log.Printf("[deploy] сервис активен; rollback-копия: %s", backup)

	// 4. Журнал запуска.
	_, logs := runCmd(client, fmt.Sprintf("journalctl -u %s -n 12 --no-pager", *serviceName))
	log.Printf("[deploy] журнал сервиса:\n%s", logs)
	log.Printf("[deploy] OK: %s -> %s (sha256 %s)", *localFile, *remoteFile, localSHA)
}

// buildAuth собирает методы аутентификации: ключ приоритетнее пароля.
func buildAuth(pass, passfile, keyPath string) ([]ssh.AuthMethod, error) {
	if keyPath == "" {
		keyPath = os.Getenv("CITP_SSH_KEY")
	}
	if keyPath == "" {
		def := filepath.Join("bin", "data", "ssh_ed25519")
		if _, err := os.Stat(def); err == nil {
			keyPath = def
		}
	}
	if keyPath != "" {
		pem, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("ключ %s: %w", keyPath, err)
		}
		signer, err := ssh.ParsePrivateKey(pem)
		if err != nil {
			return nil, fmt.Errorf("ключ %s: %w", keyPath, err)
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
	}
	if pass == "" {
		pass = os.Getenv("CITP_SSH_PASS")
	}
	if pass == "" && passfile != "" {
		b, err := os.ReadFile(passfile)
		if err != nil {
			return nil, fmt.Errorf("passfile %s: %w", passfile, err)
		}
		pass = strings.TrimSpace(string(b))
	}
	if pass == "" {
		return nil, errors.New("нет ни ключа (-key/CITP_SSH_KEY/bin/data/ssh_ed25519), ни пароля (-pass/CITP_SSH_PASS/-passfile)")
	}
	return []ssh.AuthMethod{ssh.Password(pass)}, nil
}

// buildHostKeyCallback: строгий пин fingerprint'а либо known_hosts с TOFU.
func buildHostKeyCallback(pin, knownHostsPath string) (ssh.HostKeyCallback, error) {
	if pin == "" {
		pin = os.Getenv("CITP_SSH_HOSTKEY")
	}
	if pin != "" {
		return func(_ string, _ net.Addr, k ssh.PublicKey) error {
			fp := ssh.FingerprintSHA256(k)
			if !strings.EqualFold(fp, pin) {
				return fmt.Errorf("host key НЕ совпал с пином: got %s, want %s", fp, pin)
			}
			return nil
		}, nil
	}
	if err := os.MkdirAll(filepath.Dir(knownHostsPath), 0o700); err != nil {
		return nil, err
	}
	if _, err := os.Stat(knownHostsPath); errors.Is(err, os.ErrNotExist) {
		if err := os.WriteFile(knownHostsPath, nil, 0o600); err != nil {
			return nil, err
		}
	}
	kh, err := knownhosts.New(knownHostsPath)
	if err != nil {
		return nil, err
	}
	return func(host string, addr net.Addr, k ssh.PublicKey) error {
		err := kh(host, addr, k)
		if err == nil {
			return nil
		}
		var kerr *knownhosts.KeyError
		if errors.As(err, &kerr) && len(kerr.Want) == 0 {
			// TOFU: первый контакт — печатаем fingerprint и записываем.
			entry := host
			if strings.HasSuffix(entry, ":22") {
				entry = strings.TrimSuffix(entry, ":22")
			}
			line := knownhosts.Line([]string{entry}, k)
			f, ferr := os.OpenFile(knownHostsPath, os.O_APPEND|os.O_WRONLY, 0o600)
			if ferr != nil {
				return ferr
			}
			defer f.Close()
			if _, ferr := f.WriteString(line + "\n"); ferr != nil {
				return ferr
			}
			log.Printf("[deploy] TOFU: host key %s %s записан в %s", k.Type(), ssh.FingerprintSHA256(k), knownHostsPath)
			return nil
		}
		// Известный хост с ДРУГИМ ключом — возможный MITM, стоп.
		return fmt.Errorf("host key конфликт (возможен MITM): %w", err)
	}, nil
}

// upload передаёт бинарь через stdin SSH-сессии во временный удалённый путь.
func upload(client *ssh.Client, data []byte, remotePath string) {
	session, err := client.NewSession()
	if err != nil {
		log.Fatalf("[deploy] ошибка создания SSH сессии: %v", err)
	}
	defer session.Close()
	stdin, err := session.StdinPipe()
	if err != nil {
		log.Fatalf("[deploy] ошибка stdin pipe: %v", err)
	}
	go func() {
		defer stdin.Close()
		_, _ = stdin.Write(data)
	}()
	if out, err := session.CombinedOutput("cat > " + remotePath); err != nil {
		log.Fatalf("[deploy] ошибка сохранения бинарника: %v (вывод: %s)", err, string(out))
	}
}

// rollback возвращает бэкап на место и перезапускает сервис.
func rollback(client *ssh.Client, remoteFile, backup, serviceName string) {
	log.Printf("[deploy] ОТКАТ: %s -> %s", backup, remoteFile)
	runCmd(client, fmt.Sprintf("[ -f %s ] && cp -a %s %s; systemctl start %s || true", backup, backup, remoteFile, serviceName))
}

func runCmd(client *ssh.Client, cmd string) (int, string) {
	sess, err := client.NewSession()
	if err != nil {
		log.Fatalf("[deploy] ошибка создания сессии для команды %q: %v", cmd, err)
	}
	defer sess.Close()
	out, err := sess.CombinedOutput(cmd)
	rc := 0
	if err != nil {
		var ee *ssh.ExitError
		if errors.As(err, &ee) {
			rc = ee.ExitStatus()
		} else {
			rc = -1
		}
		log.Printf("[deploy] команда %q: rc=%d (вывод: %s)", cmd, rc, strings.TrimSpace(string(out)))
	}
	return rc, string(out)
}
