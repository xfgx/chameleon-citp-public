// chaossync-client — клиент транспорта хаос-синхронизации (этап Э5).
//
// Секреты: мастер-ключ ТОЛЬКО из файла 0600 (флаг -keyfile), никогда из argv
// (argv виден в ps/powershell). Fail-closed: нет синхронизма — нет данных,
// выход с ненулевым кодом.
//
// Э5: приём через джиттер-буфер — часы сэмплов идут от ЛОКАЛЬНОГО тикера,
// датаграммы складываются в очередь. Джиттер сети не принимается за потери;
// потеря — только underrun очереди.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"chameleon/internal/chaossync"
)

func main() {
	node := flag.String("node", "", "UDP-адрес ноды host:port (обязателен)")
	keyfile := flag.String("keyfile", "chaossync-client.key", "файл мастер-ключа (0600)")
	send := flag.String("send", "", "текст кадра для отправки после синхронизма")
	selftest := flag.Bool("selftest", false, "напечатать хэш хаос-ядра и выйти")
	dur := flag.Duration("dur", 20*time.Second, "длительность прогона")
	syncTimeout := flag.Duration("sync-timeout", 25*time.Second, "таймаут захвата синхронизма (fail-closed)")
	tSec := flag.Uint64("T", 32, "период мутации T, секунд")
	coupling := flag.String("c", "", "связь Pecora-Carroll c (пусто = дефолт режима: 0.95 при m8, 0.85 при csk)")
	rate := flag.Int("rate", 200, "сэмплов/сек")
	sym := flag.Int("S", 32, "сэмплов на символ")
	batch := flag.Int("batch", 4, "сэмплов на датаграмму")
	modFlag := flag.String("mod", "m8", "модуляция carrier: m8 (дефолт, ×83 по Э-B) | csk (fallback)")
	m8s := flag.Int("m8S", 0, "M8: сэмплов на символ (0 — дефолт ядра)")
	// -config файл (key=value / key value), командная строка переопределяет.
	if cp := preScanConfigPath(); cp != "" {
		applyConfigFile(cp)
	}
	flag.Parse()

	if *selftest {
		fmt.Println(chaossync.SelftestVector())
		return
	}
	if *node == "" {
		log.Fatal("нужен -node host:port")
	}
	log.SetPrefix("[chaossync-client] ")
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	master, err := chaossync.LoadMasterKey(*keyfile)
	if err != nil {
		log.Fatalf("fail-closed: ключ не загружен: %v", err)
	}
	cpl := chaossync.Fxp(0) // 0 = дефолт режима (см. NewEndpoint)
	if *coupling != "" {
		cpl = chaossync.MustDecimal(*coupling)
	}
	mod := chaossync.ModulationM8
	switch *modFlag {
	case "m8":
	case "csk":
		mod = chaossync.ModulationCSK
	default:
		log.Fatalf("fail-closed: неизвестная модуляция %q (m8|csk)", *modFlag)
	}
	cfg := chaossync.Config{
		Master:     master,
		Rate:       *rate,
		EpochSec:   *tSec,
		Coupling:   cpl,
		SymbolS:    *sym,
		Batch:      *batch,
		Modulation: mod,
		M8S:        *m8s,
	}
	if err := cfg.Validate(); err != nil {
		log.Fatalf("fail-closed: конфиг: %v", err)
	}

	ra, err := net.ResolveUDPAddr("udp", *node)
	if err != nil {
		log.Fatalf("node: %v", err)
	}
	conn, err := net.DialUDP("udp", nil, ra)
	if err != nil {
		log.Fatalf("dial %s: %v", *node, err)
	}
	defer conn.Close()

	ep := chaossync.NewEndpoint(cfg, "c2s")

	// приёмник s2c: датаграммы в джиттер-буфер (без обработки на приходе).
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				dat := make([]byte, n)
				copy(dat, buf[:n])
				ep.EnqueueDatagram(dat, time.Now())
			}
			if err != nil {
				return
			}
		}
	}()

	log.Printf("нода %s, T=%ds c=%s rate=%d S=%d batch=%d — захват синхронизма...", *node, *tSec, *coupling, *rate, *sym, *batch)

	sent, echoed := false, false
	synced := false
	syncAt := time.Time{}
	start := time.Now()
	tk := time.NewTicker(cfg.DatagramInterval())
	defer tk.Stop()
	stat := time.NewTicker(2 * time.Second)
	defer stat.Stop()

	for time.Since(start) < *dur {
		select {
		case now := <-tk.C:
			ep.TickRx(now) // обработать принятые сэмплы по локальным часам
			dat := ep.NextDatagram(now)
			_, _ = conn.Write(dat)
			// fail-closed: не захватил синхронизм за sync-timeout — выход.
			if !synced && time.Since(start) > *syncTimeout {
				log.Printf("FAIL: синхронизм не захвачен за %v (fail-closed)", *syncTimeout)
				os.Exit(1)
			}
			if !synced && ep.Snapshot().Phased {
				synced = true
				syncAt = time.Now()
				log.Printf("СИНХРОНИЗМ+ФАЗА захвачены за %v", syncAt.Sub(start).Round(time.Millisecond))
			}
			// кадр шлём только после фазы + пауза на установление, чтобы приёмник
			// успел выровнять окна и увидеть маркер.
			if synced && !sent && *send != "" && time.Since(syncAt) > 3*time.Second {
				if err := ep.PushFrame([]byte(*send)); err == nil {
					sent = true
					log.Printf("кадр отправлен (%d байт)", len(*send))
				}
			}
			for _, f := range ep.Frames() {
				log.Printf("ЭХО от ноды: %q (epoch %d)", f.Payload, f.StartEpoch)
				if *send != "" && string(f.Payload) == *send {
					echoed = true
				}
			}
		case <-stat.C:
			s := ep.Snapshot()
			log.Printf("метрики: mode=%s phased=%v epoch=%d resid_ms=%.2e ber=%.4f loss=%d qbuf=%d jitter=%.1fms resyncs=%d frames_ok=%d",
				s.Mode, s.Phased, s.Epoch, s.ResidMS, s.BER, s.LossInferred, ep.RxQueued(), s.JitterAvgMs, s.Resyncs, s.FramesOK)
		}
	}

	s := ep.Snapshot()
	log.Printf("ФИНАЛ: mode=%s phased=%v epoch=%d resid_ms=%.3e ber=%.4f loss=%d jitter=%.2fms resyncs=%d spikes=%d frames_ok=%d badcrc=%d syncbad=%d/%d",
		s.Mode, s.Phased, s.Epoch, s.ResidMS, s.BER, s.LossInferred, s.JitterAvgMs, s.Resyncs, s.Spikes, s.FramesOK, s.FramesBadCRC, s.SyncBad, s.SyncTot)

	// fail-closed вердикт.
	if !s.Phased {
		log.Printf("FAIL: фаза не захвачена за %v", *dur)
		os.Exit(1)
	}
	if *send != "" {
		if !sent {
			log.Printf("FAIL: синхронизм не захвачен — кадр не отправлен")
			os.Exit(1)
		}
		if !echoed {
			log.Printf("FAIL: эхо кадра не получено за %v", *dur)
			os.Exit(1)
		}
		log.Printf("OK: кадр отправлен и эхо получено по хаос-звену (sync за %v)", syncAt.Sub(start).Round(time.Millisecond))
	}
}

// preScanConfigPath ищет -config/--config в argv ДО flag.Parse.
func preScanConfigPath() string {
	for i, a := range os.Args {
		if (a == "-config" || a == "--config") && i+1 < len(os.Args) {
			return os.Args[i+1]
		}
		if v, ok := strings.CutPrefix(a, "-config="); ok {
			return v
		}
		if v, ok := strings.CutPrefix(a, "--config="); ok {
			return v
		}
	}
	return ""
}

// applyConfigFile применяет key=value / "key value" из файла до flag.Parse.
// Порядок приоритета: дефолт < конфиг < командная строка. Fail-closed.
func applyConfigFile(path string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("fail-closed: конфиг %s: %v", path, err)
	}
	for ln, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var k, v string
		if i := strings.IndexByte(line, '='); i >= 0 {
			k, v = strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:])
		} else {
			f := strings.Fields(line)
			if len(f) != 2 {
				log.Fatalf("fail-closed: конфиг %s:%d: неверная строка %q", path, ln+1, line)
			}
			k, v = f[0], f[1]
		}
		if err := flag.Set(k, v); err != nil {
			log.Fatalf("fail-closed: конфиг %s:%d: %v", path, ln+1, err)
		}
	}
}
