// cdt-probe — двусторонний тестер туннеля Chaos-Dispersed Transport. Без TUN:
// работает на Windows (клиент), Linux (нода за рубежом) и в минимальном
// контейнере. «Отдельная программа, чтобы проверить туннель».
//
// NAT-traversal (честно): клиент за NAT шлёт со стабильного src-порта (fixsrc);
// нода учит ПОЛНЫЙ внешний адрес клиента (IP:порт, который NAT уже отремэпил)
// по валидным фрагментам и отвечает ему С ТОГО ЖЕ порта блока, на который
// клиент слал — так NAT-дыра совпадает точно. Forward-путь (клиент->нода)
// диспергирован по блоку портов ноды; return-путь (нода->клиент) обязан идти в
// NAT-дыру (ограничение NAT, честно).
//
// Мастер-ключ — только из файла 0600. Fail-closed: чужой шум не опознаётся.
package main

import (
	"encoding/binary"
	"flag"
	"log"
	"net"
	"sync/atomic"
	"time"

	"chameleon/internal/chaossync"
)

var (
	cSent, cRecv, cEcho, cBad atomic.Uint64
	lastPeer                  atomic.Value // *net.UDPAddr — полный выученный адрес клиента
)

func main() {
	isNode := flag.Bool("node", false, "режим ноды (эхо)")
	keyfile := flag.String("keyfile", "cdt.key", "файл мастер-ключа (0600)")
	genkey := flag.Bool("genkey", false, "создать мастер-ключ (0600) и выйти")
	peerIP := flag.String("peer", "", "IP ноды (клиенту)")
	c2nBase := flag.Int("c2nbase", 20000, "база блока портов ноды (клиент->нода)")
	c2nCount := flag.Int("c2ncount", 48, "число портов блока ноды")
	n2cPort := flag.Int("n2cport", 23500, "порт прослушивания клиента (нода->клиент)")
	rotT := flag.Uint64("T", 8, "период ротации геометрии/ключа, сек")
	probes := flag.Int("n", 150, "число зондов (клиент)")
	size := flag.Int("size", 400, "размер зонда, байт")
	intervalMs := flag.Int("interval", 4, "интервал между зондами, мс")
	flag.Parse()

	if *genkey {
		if err := chaossync.GenerateMasterKey(*keyfile); err != nil {
			log.Fatalf("genkey: %v", err)
		}
		log.Printf("мастер-ключ создан: %s (0600). Положи ТОТ ЖЕ файл на ноду — иначе не синхронизируются", *keyfile)
		return
	}

	log.SetPrefix("[cdt-probe] ")
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	master, err := chaossync.LoadMasterKey(*keyfile)
	if err != nil {
		log.Fatalf("fail-closed: ключ: %v", err)
	}

	// общие конфиги геометрии по направлениям — ДОЛЖНЫ совпадать у обеих сторон
	tuning := func() chaossync.GeomConfig {
		return chaossync.GeomConfig{MinFrag: 200, MaxFrag: 1400, MinGapUs: 0, MaxGapUs: 0, MinFlow: 1, MaxFlow: 12}
	}
	c2n := tuning()
	c2n.PortBase, c2n.PortCount, c2n.Dir = *c2nBase, *c2nCount, "c2n"
	n2c := tuning()
	n2c.PortBase, n2c.PortCount, n2c.Dir = *n2cPort, 1, "n2c"

	var outCfg, inCfg chaossync.GeomConfig
	var listenBase, listenCount int
	if *isNode {
		outCfg, inCfg = n2c, c2n
		listenBase, listenCount = *c2nBase, *c2nCount
	} else {
		outCfg, inCfg = c2n, n2c
		listenBase, listenCount = *n2cPort, 1
	}
	frag := chaossync.NewRotatingFragmenter(master, outCfg, *rotT, time.Now())
	defrag := chaossync.NewRotatingDefragmenter(master, inCfg, *rotT, time.Now())

	type inPkt struct {
		data []byte
		src  *net.UDPAddr
		sock *net.UDPConn // сокет, на который пришло (нода эширует с него — NAT-дыра совпадает)
	}
	datch := make(chan inPkt, 8192)
	var sharedSock *net.UDPConn // первый сокет — src-порт клиента (fixsrc)
	for p := listenBase; p < listenBase+listenCount; p++ {
		c, err := net.ListenUDP("udp", &net.UDPAddr{Port: p})
		if err != nil {
			continue
		}
		if p == listenBase {
			sharedSock = c
		}
		go func(cc *net.UDPConn) {
			buf := make([]byte, 2048)
			for {
				n, src, err := cc.ReadFromUDP(buf)
				if err != nil {
					return
				}
				d := make([]byte, n)
				copy(d, buf[:n])
				datch <- inPkt{d, src, cc}
			}
		}(c)
	}
	if sharedSock == nil {
		log.Fatal("fail-closed: не слушаю ни один порт")
	}

	// логгер счётчиков (раз в 2с)
	go func() {
		tk := time.NewTicker(2 * time.Second)
		for range tk.C {
			log.Printf("счётчики: sent=%d recv=%d echo=%d bad=%d", cSent.Load(), cRecv.Load(), cEcho.Load(), cBad.Load())
		}
	}()

	if *isNode {
		log.Printf("нода: блок %d..%d, эхо по CDT (де-диспергирование + ответ в NAT-дыру)", listenBase, listenBase+listenCount-1)
		for pkt := range datch {
			defrag.TickEpoch(time.Now())
			if !defrag.Ingest(pkt.data) {
				cBad.Add(1)
				continue
			}
			cRecv.Add(1)
			if pkt.src != nil {
				lastPeer.Store(pkt.src) // ПОЛНЫЙ внешний адрес клиента (IP:порт после NAT-ремапа)
			}
			for {
				m := defrag.Next()
				if m == nil {
					break
				}
				// эхо: с принявшего сокета (тот же порт блока) на полный выученный адрес
				v := lastPeer.Load()
				if v == nil {
					continue
				}
				frag.TickEpoch(time.Now())
				frag.Push(m)
				wire, _, ok := frag.EmitFinal()
				if !ok {
					continue
				}
				if _, err := pkt.sock.WriteToUDP(wire, v.(*net.UDPAddr)); err == nil {
					cEcho.Add(1)
				}
			}
		}
	}

	// клиент: приём эхо + метрики
	sendTimes := map[uint64]time.Time{}
	var rttSum int64
	go func() {
		for pkt := range datch {
			defrag.TickEpoch(time.Now())
			if !defrag.Ingest(pkt.data) {
				cBad.Add(1)
				continue
			}
			cRecv.Add(1)
			for {
				m := defrag.Next()
				if m == nil {
					break
				}
				if len(m) >= 8 {
					seq := binary.BigEndian.Uint64(m)
					if t0, ok := sendTimes[seq]; ok {
						rttSum += time.Since(t0).Microseconds()
						cEcho.Add(1)
						delete(sendTimes, seq)
					}
				}
			}
		}
	}()

	log.Printf("клиент: %d зондов по %d байт -> %s блок %d..%d (дисперсия, src-порт стабилен)", *probes, *size, *peerIP, *c2nBase, *c2nBase+*c2nCount-1)
	start := time.Now()
	for i := 0; i < *probes; i++ {
		msg := make([]byte, *size)
		binary.BigEndian.PutUint64(msg, uint64(i))
		sendTimes[uint64(i)] = time.Now()
		// fixsrc: шлём со sharedSock (стабильный src-порт) на диспергированный порт ноды
		frag.TickEpoch(time.Now())
		frag.Push(msg)
		if wire, g, ok := frag.EmitFinal(); ok {
			dst, _ := net.ResolveUDPAddr("udp", net.JoinHostPort(*peerIP, itoa(g.DestPort)))
			if _, err := sharedSock.WriteToUDP(wire, dst); err == nil {
				cSent.Add(1)
			}
		}
		time.Sleep(time.Duration(*intervalMs) * time.Millisecond)
	}
	time.Sleep(3 * time.Second)
	el := time.Since(start).Seconds()
	echoed := cEcho.Load()
	lost := uint64(*probes) - echoed
	avgRtt := float64(0)
	if echoed > 0 {
		avgRtt = float64(rttSum) / float64(echoed) / 1000
	}
	log.Printf("РЕЗУЛЬТАТ: зондов=%d эхо=%d потерь=%d (%.1f%%), RTT avg=%.1f мс, throughput=%.2f Мбит/с (RTT-путь)",
		*probes, echoed, lost, 100*float64(lost)/float64(*probes), avgRtt,
		float64(uint64(*probes)*uint64(*size)*2*8)/el/1e6)
	if echoed > 0 {
		log.Printf("ТУННЕЛЬ РАБОТАЕТ cross-border: двусторонний round-trip через дисперсию подтверждён")
	} else {
		log.Printf("ТУННЕЛЬ НЕ ОТВЕЧАЕТ: эхо не пришло (нода/ключи/эпоха/NAT)")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [8]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}
