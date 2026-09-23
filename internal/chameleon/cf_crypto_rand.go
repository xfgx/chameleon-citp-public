package chameleon

// cf_crypto_rand.go — tiny crypto/rand shim so the Control Fabric stays
// self-contained and testable without importing the rest of the tree.

import "crypto/rand"

// cryptoRandRead reads len(p) cryptographically-secure random bytes.
func cryptoRandRead(p []byte) (int, error) {
	return rand.Read(p)
}
