package chameleon

import (
	"sync"
	"testing"
	"time"
)

// TestShaperIdempotentStop проверяет, что повторный и параллельный вызов Stop() безопасен
func TestShaperIdempotentStop(t *testing.T) {
	// Создаем пару подключений или эхо-сервер
	conn := &Conn{seed: make([]byte, 32)}
	shaper := conn.StartShaper(50*time.Millisecond, 10*time.Millisecond, 10, 50, "test")

	// 1. Первый Stop
	shaper.Stop()

	// 2. Второй Stop (проверка идемпотентности)
	shaper.Stop()

	// 3. Параллельные вызовы Stop
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			shaper.Stop()
		}()
	}
	wg.Wait()
}
