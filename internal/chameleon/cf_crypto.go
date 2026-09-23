package chameleon

// cf_crypto.go — cryptographic primitives for the Control Fabric.
//
// These mirror the conventions used by the CITP core (ChaCha20-Poly1305 AEAD,
// HKDF-SHA256, HMAC-SHA256) but are self-contained so the Control Fabric can
// be compiled and unit-tested independently of the rest of internal/chameleon.
// In the real tree these helpers would reuse internal/chameleon/keys.go and
// internal/chameleon/mask.go instead of re-defining them.

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// ErrCrypto is returned for any AEAD/HKDF failure.
var ErrCrypto = errors.New("control-fabric: crypto failure")

// DeriveSessionSecret derives a 32-byte session secret from a master seed
// using HKDF-SHA256 (matches the CITP "seed" derivation used by
// DeriveStreamSecret in migration.go).
func DeriveSessionSecret(seed []byte) []byte {
	out := make([]byte, 32)
	r := hkdf.New(sha256.New, seed, []byte("citp-control-fabric"), []byte("session-secret"))
	_, _ = io.ReadFull(r, out)
	return out
}

// AEADEncrypt encrypts plaintext with ChaCha20-Poly1305 using a random nonce.
// Output layout: nonce(12) || ciphertext.
func AEADEncrypt(key, plaintext []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, ErrCrypto
	}
	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := io.ReadFull(randReader{}, nonce); err != nil {
		return nil, err
	}
	ct := a.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ct...), nil
}

// AEADDecrypt decrypts a nonce||ciphertext blob produced by AEADEncrypt.
func AEADDecrypt(key, blob []byte) ([]byte, error) {
	if len(blob) < chacha20poly1305.NonceSize+chacha20poly1305.Overhead {
		return nil, ErrCrypto
	}
	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce, ct := blob[:chacha20poly1305.NonceSize], blob[chacha20poly1305.NonceSize:]
	return a.Open(nil, nonce, ct, nil)
}

// HMACSession returns HMAC-SHA256(key, data) — used for CITPObject AuthTag
// and ResolutionObject signatures.
func HMACSession(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

type randReader struct{}

func (randReader) Read(p []byte) (int, error) {
	return cryptoRandRead(p)
}
