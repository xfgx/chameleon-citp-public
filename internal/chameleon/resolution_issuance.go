package chameleon

import (
	"crypto/sha256"
	"errors"
	"sync"
	"time"
)

const maxIssuedResolutions = 1024

type resolutionIssuance struct {
	mu      sync.Mutex
	objects map[[32]byte]int64
}

// The session seed is known to both peers. A valid HMAC alone therefore does
// not prove that this server resolved and issued the object to this client.
func (s *resolutionIssuance) remember(ro *ResolutionObject, now time.Time) error {
	encoded := ro.Encode()
	if encoded == nil || ro.Expiry <= now.Unix() {
		return errors.New("resolution issuance: invalid object")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.objects == nil {
		s.objects = make(map[[32]byte]int64)
	}
	for key, expiry := range s.objects {
		if expiry <= now.Unix() {
			delete(s.objects, key)
		}
	}
	key := sha256.Sum256(encoded)
	if _, exists := s.objects[key]; !exists && len(s.objects) >= maxIssuedResolutions {
		return errors.New("resolution issuance: outstanding object limit")
	}
	s.objects[key] = ro.Expiry
	return nil
}

func (s *resolutionIssuance) verify(ro *ResolutionObject, now time.Time) error {
	encoded := ro.Encode()
	if encoded == nil {
		return errors.New("resolution issuance: invalid encoding")
	}
	key := sha256.Sum256(encoded)
	s.mu.Lock()
	defer s.mu.Unlock()
	expiry, ok := s.objects[key]
	if !ok || expiry <= now.Unix() {
		return errors.New("resolution object was not issued by this session")
	}
	return nil
}
