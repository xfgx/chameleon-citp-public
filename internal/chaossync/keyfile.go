package chaossync

// keyfile.go — мастер-ключ звена: генерация и загрузка из файла.
//
// Правила безопасности (сквозное требование «секреты вне cmdline»):
//   - ключ НИКОГДА не передаётся аргументом процесса (виден в ps/powershell);
//   - файл ключа — base64(32 байта), права 0600, иначе отказ (fail-closed);
//   - на Windows проверка прав пропускается (ACL вместо POSIX-прав).

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"runtime"
	"strings"
)

// MasterKeyLen — длина мастер-ключа в байтах.
const MasterKeyLen = 32

// GenerateMasterKey создаёт новый мастер-ключ в path (0600, без перезаписи).
func GenerateMasterKey(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("chaossync: ключ %s уже существует — не перезаписываю", path)
	}
	var k [MasterKeyLen]byte
	if _, err := rand.Read(k[:]); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(k[:])+"\n"), 0o600)
}

// ParseMasterKey разбирает мастер-ключ из base64 (std или raw-url), без файла.
func ParseMasterKey(b64 string) ([]byte, error) {
	b64 = strings.TrimSpace(b64)
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(b64)
	}
	if err != nil {
		b, err = base64.RawURLEncoding.DecodeString(b64)
	}
	if err != nil {
		return nil, fmt.Errorf("chaossync: ключ не base64: %w", err)
	}
	if len(b) != MasterKeyLen {
		return nil, fmt.Errorf("chaossync: ключ %d байт, нужно %d", len(b), MasterKeyLen)
	}
	return b, nil
}

// LoadMasterKey читает мастер-ключ из файла, проверяя права (fail-closed).
func LoadMasterKey(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("chaossync: ключ %s: %w", path, err)
	}
	if runtime.GOOS != "windows" {
		if perm := fi.Mode().Perm(); perm != 0o600 {
			return nil, fmt.Errorf("chaossync: ключ %s имеет права %o, нужно 0600 — отказ", path, perm)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseMasterKey(string(raw))
}
