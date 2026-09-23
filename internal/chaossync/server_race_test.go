package chaossync

// Регрессионный тест: ServerMux обращаются из НЕСКОЛЬКИХ горутин одновременно
// (как в реальной ноде: read-цикл, тиковая горутина, http-метрики). Без
// мьютекса на карте peers это давало «fatal error: concurrent map read and
// map write» (краш ноды под фоновым шумом интернета, этап Э5).

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestServerMuxConcurrent(t *testing.T) {
	master := bytes.Repeat([]byte{0x42}, 32)
	cfg := Config{Master: master, Rate: 1000, EpochSec: 8, Coupling: MustDecimal("0.85"), SymbolS: 32, Batch: 4}
	mux := NewServerMux(cfg)
	now := time.Unix(1_700_000_000, 0)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Горутина read-цикла: Enqueue/Handle создают НОВЫХ пиров (запись в map).
	wg.Add(1)
	go func() {
		defer wg.Done()
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			i++
			addr := fmt.Sprintf("peer%d", i%40) // карусель новых источников
			mux.Enqueue(make([]byte, 8), addr, now)
			mux.Handle(make([]byte, 8), addr, now)
		}
	}()

	// Тиковая горутина: обход peers + PeerFrames + PushFrame.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			mux.TickPeers(now)
			mux.Tick(now)
			mux.PeerFrames("peer1")
			_ = mux.PushFrame([]byte("x"))
		}
	}()

	// Горутина метрик/очистки: PeerCount/PeerSnapshot/Cleanup.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			mux.Cleanup(now)
			mux.PeerCount()
			mux.PeerSnapshot("peer1")
		}
	}()

	time.Sleep(400 * time.Millisecond)
	close(stop)
	wg.Wait()
}
