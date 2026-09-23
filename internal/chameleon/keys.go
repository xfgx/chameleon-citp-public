package chameleon

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// Статический ключ ноды (long-term identity). Используется ТОЛЬКО для
// аутентификации клиента в рукопожатии: сессионные ключи выводятся из
// эфемерного ECDH, поэтому компрометация статического ключа не раскрывает
// записанные ранее сеансы (forward secrecy).

// GenerateNodeKey генерирует статическую пару X25519.
// Возвращает приватный и публичный ключи в base64 (raw, 32 байта).
func GenerateNodeKey() (privB64, pubB64 string, err error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(priv.Bytes()),
		base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

// ParseNodePubKey разбирает публичный ключ ноды из base64.
func ParseNodePubKey(b64 string) (*ecdh.PublicKey, error) {
	b64 = strings.TrimSpace(b64)
	raw, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		if raw, err = base64.StdEncoding.DecodeString(b64); err != nil {
			return nil, fmt.Errorf("публичный ключ: не base64: %w", err)
		}
	}
	pub, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("публичный ключ: %w", err)
	}
	return pub, nil
}

// ParseNodePrivKey разбирает приватный ключ ноды из base64.
func ParseNodePrivKey(b64 string) (*ecdh.PrivateKey, error) {
	b64 = strings.TrimSpace(b64)
	raw, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		if raw, err = base64.StdEncoding.DecodeString(b64); err != nil {
			return nil, fmt.Errorf("приватный ключ: не base64: %w", err)
		}
	}
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("приватный ключ: %w", err)
	}
	return priv, nil
}

// SaveNodeKey записывает приватный ключ в файл (0600).
func SaveNodeKey(path string, privB64 string) error {
	return os.WriteFile(path, []byte(privB64+"\n"), 0o600)
}

// LoadNodeKey читает приватный ключ из файла.
func LoadNodeKey(path string) (*ecdh.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseNodePrivKey(string(b))
}
