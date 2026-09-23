// cdt-server — нода Chaos-Dispersed Transport: слушает блок портов (одна
// машина, адресное пространство портов), де-диспергирует фрагменты по
// хаос-узору, собирает поток обратно и меряет реальную пропускную способность.
//
// Fail-closed: фрагмент без валидного AEAD-тега и nonce из хаос-расписания
// отбрасывается молча (шум/чужой ключ/сканер). Мастер-ключ — только из файла
// 0600, никогда из argv.
//
// Многопоточность: Defragmenter НЕ потокобезопасен — все датаграммы блока
// сливаются через один канал в одну ingest-горутину (нет разделяемого состояния
// между слушателями портов).
package main

import (
	"flag"
	"log"
	"net"
	"time"

	"chameleon/internal/chaossync"
)

func main() {
	keyfile := flag.String("keyfile", "cdt.key", "файл мастер-ключа (0600)")
	portBase := flag.Int("portbase", 20000, "первый порт блока ноды")
	portCount := flag.Int("portcount", 48, "число портов в блоке")
	rotT := flag.Uint64("T", 8, "период мутации геометрии/ключа, сек — ротация эпох хаоса")
	report := flag.Duration("report", 5*time.Second, "период отчёта о throughput")
	flag.Parse()

	log.SetPrefix("[cdt-server] ")
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	master, err := chaossync.LoadMasterKey(*keyfile)
	if err != nil {
		log.Fatalf("fail-closed: ключ не загружен: %v", err)
	}
	cfg := chaossync.GeomConfig{PortBase: *portBase, PortCount: *portCount}
	defrag := chaossync.NewRotatingDefragmenter(master, cfg, *rotT, time.Now())

	// единый канал датаграмм -> одна ingest-горутина (нет data race).
	datch := make(chan []byte, 8192)
	bound := 0
	for p := *portBase; p < *portBase+*portCount; p++ {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: p})
		if err != nil {
			log.Printf("bind :%d занят/ошибка: %v (пропускаю)", p, err)
			continue
		}
		bound++
		go func(c *net.UDPConn, port int) {
			buf := make([]byte, 2048)
			for {
				n, _, err := c.ReadFromUDP(buf)
				if err != nil {
					return
				}
				dat := make([]byte, n)
				copy(dat, buf[:n])
				datch <- dat
			}
		}(conn, p)
	}
	if bound == 0 {
		log.Fatal("fail-closed: не удалось слушать ни один порт блока")
	}
	log.Printf("слушаю блок портов %d..%d (%d шт), эпоха %d — де-диспергирование по хаос-узору",
		*portBase, *portBase+*portCount-1, bound, chaossync.EpochFor(time.Now(), *rotT))

	var totalBytes, totalFrags, okFrags uint64
	start := time.Now()

	go func() {
		tk := time.NewTicker(*report)
		for range tk.C {
			el := time.Since(start).Seconds()
			mbps := float64(totalBytes*8) / el / 1e6
			log.Printf("принято: фрагментов=%d (опознано=%d, шум/чужие=%d), payload=%d байт, %.2f Мбит/с",
				totalFrags, okFrags, totalFrags-okFrags, totalBytes, mbps)
		}
	}()

	for dat := range datch {
		defrag.TickEpoch(time.Now()) // ротация по эпохам (та же горутина, без гонки)
		totalFrags++
		if defrag.Ingest(dat) {
			okFrags++
			// собираем непрерывный поток
			for {
				chunk := defrag.Next()
				if chunk == nil {
					break
				}
				totalBytes += uint64(len(chunk))
			}
		}
	}
}
