// chaossync-server — нода транспорта хаос-синхронизации (этап Э5).
//
// Fail-closed по построению: нода молчит на ВСЁ, пока источник не доказал
// знание мастер-ключа самим фактом синхронизма (residual его потока падает
// до уровня квантования — без ключа недостижимо). Снаружи UDP-порт
// неотличим от фильтрованного. Продолжение философии blackhole из Priority 0.
//
// Секреты: мастер-ключ ТОЛЬКО из файла 0600 (флаг -keyfile), никогда из argv.
// Метрики: HTTP на loopback (127.0.0.1), наружу не светятся.
// Э5: приём через джиттер-буфер — обработка по локальным часам (TickPeers),
// датаграммы в FIFO (Enqueue); джиттер сети не принимается за потери.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"chameleon/internal/chaossync"
)

func main() {
	listen := flag.String("listen", ":15353", "UDP-адрес прослушивания ноды")
	keyfile := flag.String("keyfile", "chaossync-server.key", "файл мастер-ключа (0600)")
	metricsAddr := flag.String("metrics", "127.0.0.1:19090", "HTTP-метрики (только loopback)")
	tSec := flag.Uint64("T", 32, "период мутации T, секунд")
	coupling := flag.String("c", "", "связь Pecora-Carroll c (пусто = дефолт режима: 0.95 при m8, 0.85 при csk)")
	rate := flag.Int("rate", 200, "сэмплов/сек (50..4000)")
	sym := flag.Int("S", 32, "сэмплов на символ")
	batch := flag.Int("batch", 4, "сэмплов на UDP-датаграмму (1..8)")
	modFlag := flag.String("mod", "m8", "модуляция carrier: m8 (дефолт, ×83 по Э-B) | csk (fallback)")
	m8s := flag.Int("m8S", 0, "M8: сэмплов на символ (0 — дефолт ядра)")
	genkey := flag.Bool("genkey", false, "создать keyfile (0600) и выйти")
	flag.Parse()

	log.SetPrefix("[chaossync-server] ")
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if *genkey {
		if err := chaossync.GenerateMasterKey(*keyfile); err != nil {
			log.Fatalf("genkey: %v", err)
		}
		log.Printf("ключ создан: %s (0600)", *keyfile)
		return
	}

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

	ua, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		log.Fatalf("listen udp %s: %v", *listen, err)
	}
	defer conn.Close()

	mux := chaossync.NewServerMux(cfg)

	var mu sync.Mutex
	addrs := map[string]*net.UDPAddr{}

	// HTTP-метрики на loopback.
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		list := make([]string, 0, len(addrs))
		for a := range addrs {
			list = append(list, a)
		}
		mu.Unlock()
		tot, prov := mux.PeerCount()
		peers := map[string]chaossync.Snapshot{}
		for _, a := range list {
			if s := mux.PeerSnapshot(a); s != nil {
				peers[a] = *s
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"now":          time.Now().UTC().Format(time.RFC3339),
			"peers_total":  tot,
			"peers_proven": prov,
			"peers":        peers,
		})
	})
	go func() {
		log.Printf("метрики: http://%s/metrics", *metricsAddr)
		if err := http.ListenAndServe(*metricsAddr, nil); err != nil {
			log.Printf("metrics http: %v", err)
		}
	}()

	// Тактовый тикер ноды: обработать c2s-очереди пиров (TickPeers) и
	// сгенерировать+разослать s2c-датаграмму (Tick) — всё по локальным часам.
	go func() {
		tk := time.NewTicker(cfg.DatagramInterval())
		defer tk.Stop()
		for now := range tk.C {
			for _, a := range mux.TickPeers(now) {
				log.Printf("peer %s: синхронизм доказан — ключ подтверждён динамикой, s2c разрешён", a)
			}
			// эхо проверенных кадров обратно в s2c (тест жизнеспособности звена)
			mu.Lock()
			list := make([]string, 0, len(addrs))
			for a := range addrs {
				list = append(list, a)
			}
			mu.Unlock()
			for _, a := range list {
				for _, f := range mux.PeerFrames(a) {
					log.Printf("peer %s: кадр %d байт (epoch %d): %q", a, len(f.Payload), f.StartEpoch, f.Payload)
					_ = mux.PushFrame(f.Payload)
				}
			}
			targets, dat := mux.Tick(now)
			for _, a := range targets {
				mu.Lock()
				ra := addrs[a]
				mu.Unlock()
				if ra != nil {
					_, _ = conn.WriteToUDP(dat, ra)
				}
			}
		}
	}()

	// периодическая чистка недоказавших/молчащих + сводка в лог.
	go func() {
		tk := time.NewTicker(5 * time.Second)
		defer tk.Stop()
		for now := range tk.C {
			mux.Cleanup(now)
			tot, prov := mux.PeerCount()
			log.Printf("пиры: всего=%d доказано=%d", tot, prov)
		}
	}()

	log.Printf("слушаю UDP %s, T=%ds c=%s rate=%d S=%d batch=%d — fail-closed (молчу до доказательства ключа)",
		*listen, *tSec, *coupling, *rate, *sym, *batch)

	buf := make([]byte, 2048)
	for {
		n, ra, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("read: %v", err)
			continue
		}
		key := ra.String()
		mu.Lock()
		addrs[key] = ra
		mu.Unlock()
		dat := make([]byte, n)
		copy(dat, buf[:n])
		mux.Enqueue(dat, key, time.Now())
	}
}
