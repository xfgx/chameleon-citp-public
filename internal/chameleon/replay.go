package chameleon

import (
	"sync"
	"time"
)

// replayCache — защита от повторного воспроизведения рукопожатия.
// Зонд, записавший валидный client hello и проигравший его позже,
// получает тот же ответ, что и мусор: молчание. Без этого активный
// зондирующий мог бы отличить ноду от «мёртвого» сервиса.
const maxReplayEntries = 8192

type replayCache struct {
	mu   sync.Mutex
	seen map[[16]byte]time.Time // nonce → истечение
}

func newReplayCache() *replayCache {
	return &replayCache{seen: make(map[[16]byte]time.Time)}
}

// seenOrAdd возвращает true, если nonce уже встречался (и не истёк).
func (r *replayCache) seenOrAdd(nonce [16]byte, ttl time.Duration) bool {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	// Ленивая чистка и жесткий предел: при переполнении fail closed.
	if len(r.seen) >= maxReplayEntries {
		for k, exp := range r.seen {
			if !now.Before(exp) {
				delete(r.seen, k)
			}
		}
	}
	if exp, ok := r.seen[nonce]; ok && now.Before(exp) {
		return true
	}
	if len(r.seen) >= maxReplayEntries {
		return true
	}
	r.seen[nonce] = now.Add(ttl)
	return false
}
