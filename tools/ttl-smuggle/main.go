// Command ttl-smuggle — Sub-Horizon TTL Smuggling (CITP v3.0 / Chameleon).
//
//	mode send:     клиент-фантом; кадры летят к decoy-цели с TTL, которого
//	               хватает ровно до TAP-узла: дальше пакет уничтожается
//	               маршрутизатором (TTL Expired), не достигая decoy.
//	mode recv:     TAP-узел перехвата; слушает UDP и восстанавливает поток.
//	mode selftest: локальная сквозная проверка на loopback (TTL не тратится).
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"chameleon/internal/chameleon"
)

const defaultSecret = "<REDACTED>"

func main() {
	mode := flag.String("mode", "send", "режим: send | recv | selftest")
	target := flag.String("target", "1.1.1.1", "decoy-адрес, в сторону которого летят пакеты")
	port := flag.Int("port", 443, "UDP-порт decoy / TAP-листенера")
	ttl := flag.Int("ttl", 8, "IP TTL: должно хватать ровно до узла перехвата")
	secret := flag.String("secret", defaultSecret, "общий секрет (PSK) для HKDF")
	msg := flag.String("msg", "CITP-SUB-HORIZON-PAYLOAD-OK", "скрытое сообщение")
	count := flag.Int("count", 5, "количество пакетов")
	interval := flag.Duration("interval", time.Second, "интервал между отправками")
	listen := flag.String("listen", "0.0.0.0", "адрес прослушивания TAP-узла")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch *mode {
	case "send":
		runSender(*target, *port, *ttl, *secret, *msg, *count, *interval)
	case "recv":
		runReceiver(ctx, *listen, *port, *secret)
	case "selftest":
		if !runSelftest(*secret, *count) {
			os.Exit(1)
		}
	default:
		fmt.Printf("Неизвестный режим %q: используйте send, recv или selftest\n", *mode)
		os.Exit(2)
	}
}

func runSender(targetHost string, port, ttl int, secret, message string, count int, interval time.Duration) {
	sm, err := chameleon.NewTTLSmuggler(secret)
	if err != nil {
		log.Fatalf("smuggler: %v", err)
	}
	dst := fmt.Sprintf("%s:%d", targetHost, port)
	sender, err := chameleon.NewTTLSender(sm, dst, ttl)
	if err != nil {
		log.Fatalf("sender: %v", err)
	}
	defer sender.Close()

	log.Printf("[SENDER] Sub-Horizon TTL Smuggler активен")
	log.Printf("[SENDER] Decoy target : %s (TTL=%d, AES-256-GCM)", dst, ttl)
	for seq := uint64(1); seq <= uint64(count); seq++ {
		payload := fmt.Sprintf("%s [seq=%d, ts=%d]", message, seq, time.Now().UnixNano())
		n, err := sender.Send(seq, []byte(payload))
		if err != nil {
			log.Printf("[SENDER] ошибка отправки #%d: %v", seq, err)
			continue
		}
		log.Printf("[SENDER] пакет #%d ушёл (%d байт, TTL=%d)", seq, n, ttl)
		if seq < uint64(count) {
			time.Sleep(interval)
		}
	}
	log.Printf("[SENDER] передача завершена: пакеты умрут по TTL за узлом перехвата, decoy их не увидит")
}

func runReceiver(ctx context.Context, listenAddr string, port int, secret string) {
	sm, err := chameleon.NewTTLSmuggler(secret)
	if err != nil {
		log.Fatalf("smuggler: %v", err)
	}
	recv, err := chameleon.NewTTLReceiver(sm, fmt.Sprintf("%s:%d", listenAddr, port))
	if err != nil {
		log.Fatalf("receiver: %v", err)
	}
	defer recv.Close()

	log.Printf("[RECV] TAP-узел слушает %s — ждём фантомные пакеты до истечения их TTL...", recv.LocalAddr())
	errCh := make(chan error, 1)
	go func() {
		for {
			fr, err := recv.ReadFrame()
			if err != nil {
				errCh <- err
				return
			}
			log.Printf("[RECV] ПЕРЕХВАЧЕН ПАКЕТ: src=%s ttl=%d seq=%d size=%d payload=%q",
				fr.Src, fr.TTL, fr.Seq, fr.Size, fr.Payload)
		}
	}()
	select {
	case <-ctx.Done():
		log.Printf("[RECV] завершение по сигналу")
	case err := <-errCh:
		log.Printf("[RECV] ошибка сокета: %v", err)
	}
}

// runSelftest гоняет кадры через реальный UDP на loopback: TTL не тратится,
// зато проверяется весь путь криптографии и разбора. true при успехе.
func runSelftest(secret string, count int) bool {
	sm, err := chameleon.NewTTLSmuggler(secret)
	if err != nil {
		log.Printf("selftest: %v", err)
		return false
	}
	recv, err := chameleon.NewTTLReceiver(sm, "127.0.0.1:0")
	if err != nil {
		log.Printf("selftest: receiver: %v", err)
		return false
	}
	defer recv.Close()
	sender, err := chameleon.NewTTLSender(sm, recv.LocalAddr().String(), 64)
	if err != nil {
		log.Printf("selftest: sender: %v", err)
		return false
	}
	defer sender.Close()
	_ = recv.SetReadDeadline(time.Now().Add(5 * time.Second))

	log.Printf("[SELFTEST] loopback %s, %d пакетов...", recv.LocalAddr(), count)
	for seq := uint64(1); seq <= uint64(count); seq++ {
		payload := fmt.Sprintf("selftest-payload-%d", seq)
		if _, err := sender.Send(seq, []byte(payload)); err != nil {
			log.Printf("[SELFTEST] send #%d: %v", seq, err)
			return false
		}
	}
	ok := 0
	for seq := uint64(1); seq <= uint64(count); seq++ {
		fr, err := recv.ReadFrame()
		if err != nil {
			log.Printf("[SELFTEST] read #%d: %v", seq, err)
			break
		}
		want := fmt.Sprintf("selftest-payload-%d", seq)
		if fr.Seq == seq && string(fr.Payload) == want {
			ok++
			log.Printf("[SELFTEST] кадр #%d OK (ttl=%d, %d байт на проводе)", seq, fr.TTL, fr.Size)
		} else {
			log.Printf("[SELFTEST] кадр #%d ПОВРЕЖДЁН", seq)
		}
	}
	if ok == count {
		log.Printf("[SELFTEST] PASS: %d/%d кадров доставлено и аутентифицировано", ok, count)
		return true
	}
	log.Printf("[SELFTEST] FAIL: %d/%d", ok, count)
	return false
}
