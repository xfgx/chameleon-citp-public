// cdt-client — клиент Chaos-Dispersed Transport: растворяет поток в фрагменты
// и разбрасывает их по блоку портов ноды через реальный UDP, по хаос-геометрии
// (порт/размер/интервал/churn src-порта). Меряет реальную пропускную
// способность и наблюдаемую геометрию (что видит цензор на проводе).
//
// Мастер-ключ — только из файла 0600. Src-порт микро-потока меняем перевыпуском
// сокета (OS даёт свежий эфемерный порт) — именно так рвётся 5-tuple.
package main

import (
	"flag"
	"fmt"
	"log"
	"math"
	"net"
	"time"

	"chameleon/internal/chaossync"
)

func main() {
	keyfile := flag.String("keyfile", "cdt.key", "файл мастер-ключа (0600)")
	node := flag.String("node", "", "IP ноды (обязателен)")
	portBase := flag.Int("portbase", 20000, "первый порт блока ноды")
	portCount := flag.Int("portcount", 48, "число портов в блоке")
	sizeMB := flag.Int("size", 5, "объём для отправки, МБ")
	rotT := flag.Uint64("T", 8, "период мутации геометрии/ключа, сек — ротация эпох хаоса")
	maxGapUs := flag.Int("maxgap", 400, "макс. межпакетный интервал, мкс (меньше = быстрее)")
	flag.Parse()

	log.SetPrefix("[cdt-client] ")
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if *node == "" {
		log.Fatal("нужен -node <ip>")
	}
	master, err := chaossync.LoadMasterKey(*keyfile)
	if err != nil {
		log.Fatalf("fail-closed: ключ не загружен: %v", err)
	}
	// геометрия: явный блок портов + управляемый интервал (автопилот-кноб).
	cfg := chaossync.GeomConfig{PortBase: *portBase, PortCount: *portCount, MinFrag: 200, MaxFrag: 1400, MinGapUs: 0, MaxGapUs: *maxGapUs, MinFlow: 1, MaxFlow: 12}
	frag := chaossync.NewRotatingFragmenter(master, cfg, *rotT, time.Now())

	payload := make([]byte, *sizeMB<<20)
	for i := range payload {
		payload[i] = byte(i*31 + 13)
	}
	frag.Push(payload)

	type tup struct{ dst, size int }
	tuples := map[tup]int{}
	var gaps []int
	var conn *net.UDPConn
	var sentBytes, sentFrags int64
	start := time.Now()

	for {
		frag.TickEpoch(time.Now()) // ротация геометрии/ключа по эпохам
		wire, g, ok := frag.Emit()
		if !ok {
			wire, g, ok = frag.EmitFinal()
			if !ok {
				break
			}
		}
		if g.NewFlow || conn == nil {
			if conn != nil {
				conn.Close()
			}
			// свежий эфемерный src-порт = churn микро-потока (рвётся 5-tuple)
			c, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
			if err != nil {
				log.Fatalf("socket: %v", err)
			}
			conn = c
		}
		dst, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", *node, g.DestPort))
		if _, err := conn.WriteToUDP(wire, dst); err != nil {
			log.Printf("send: %v", err)
		}
		tuples[tup{g.DestPort, len(wire)}]++
		gaps = append(gaps, g.GapUs)
		sentBytes += int64(len(wire))
		sentFrags++
		if g.GapUs > 0 {
			time.Sleep(time.Duration(g.GapUs) * time.Microsecond)
		}
	}
	if conn != nil {
		conn.Close()
	}
	el := time.Since(start).Seconds()
	mbps := float64(sentBytes*8) / el / 1e6

	log.Printf("ОТПРАВЛЕНО: %d байт полезных за %.2fс (%d фрагментов) = %.2f Мбит/с по UDP на блок портов",
		len(payload), el, sentFrags, mbps)
	log.Printf("геометрия на проводе: уникальных (dstport,size)=%d из %d фрагментов, энтропия gap=%.2f бит",
		len(tuples), sentFrags, entropyOf(gaps))
}

func entropyOf(vals []int) float64 {
	counts := map[int]int{}
	for _, v := range vals {
		counts[v]++
	}
	n := float64(len(vals))
	h := 0.0
	for _, c := range counts {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
