// cdt-vpn — кросс-платформенный TUN↔CDT мост: несёт настоящий IP-трафик через
// Chaos-Dispersed Transport. Это и есть Windows-клиент VPN: Wintun на Windows,
// /dev/net/tun на Linux-ноде. Логика моста (дисперсия, Dir-разделение, fixsrc,
// динамическое обучение адреса peer'а) платформенно-независима и доказана;
// платформенно-зависима только TUN-часть (см. tun_linux.go / tun_windows.go).
//
// Надёжность: мост несёт СЫРОЙ IP; внутренний TCP приложения надёжен end-to-end
// (потерянный фрагмент = потерянный IP-пакет, TCP перешлёт). Поэтому не нужен
// отдельный reliable-слой поверх CDT.
package main

import (
	"flag"
	"log"
	"net"
	"sync/atomic"
	"time"

	"chameleon/internal/chaossync"
)

// счётчики стадий моста (отладка/метрики)
var (
	cTunRead  atomic.Uint64 // прочитано IP-пакетов из TUN
	cFragSent atomic.Uint64 // отправлено фрагментов в peer
	cUdpRecv  atomic.Uint64 // принято UDP-датаграмм от peer
	cIngestOK atomic.Uint64 // опознано фрагментов (AEAD+nonce сошлись)
	cTunWrite atomic.Uint64 // записано IP-пакетов в TUN
)

// udpPkt — датаграмма + адрес отправителя.
type udpPkt struct {
	data []byte
	src  *net.UDPAddr
}

// lastPeerIP — адрес клиента от ВАЛИДНЫХ (расшифрованных) фрагментов. Нода
// отвечает ему; учится от прошедших AEAD фрагментов, не от шума сканеров.
var lastPeerIP atomic.Value // string

func main() {
	keyfile := flag.String("keyfile", "cdt.key", "файл мастер-ключа (0600)")
	genkey := flag.Bool("genkey", false, "создать мастер-ключ (0600) и выйти")
	tunName := flag.String("tun", "cdt0", "имя TUN-адаптера")
	tunIP := flag.String("tunip", "", "мой туннельный IP/CIDR (обязателен)")
	peerHost := flag.String("peerhost", "", "реальный IP peer'а для отправки (обязателен на клиенте)")
	listenBase := flag.Int("listenbase", 23000, "первый порт МОЕГО блока (приём)")
	listenCount := flag.Int("listencount", 48, "число портов моего блока")
	peerBase := flag.Int("peerbase", 20000, "первый порт блока PEER'а (куда шлю)")
	peerCount := flag.Int("peercount", 48, "число портов блока peer'а")
	outDir := flag.String("outdir", "c2n", "Dir исходящего направления")
	inDir := flag.String("indir", "n2c", "Dir входящего направления")
	rotT := flag.Uint64("T", 8, "период ротации геометрии/ключа, сек")
	maxGapUs := flag.Int("maxgap", 150, "макс. межпакетный интервал, мкс")
	fixsrc := flag.Bool("fixsrc", false, "клиент за NAT: фиксированный src-порт (=порту прослушивания)")
	flag.Parse()

	log.SetPrefix("[cdt-vpn] ")
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if *genkey {
		if err := chaossync.GenerateMasterKey(*keyfile); err != nil {
			log.Fatalf("genkey: %v", err)
		}
		log.Printf("мастер-ключ создан: %s (0600). Положи ТОТ ЖЕ файл на ноду и клиент", *keyfile)
		return
	}
	if *tunIP == "" {
		log.Fatal("нужен -tunip (туннельный IP/CIDR)")
	}
	master, err := chaossync.LoadMasterKey(*keyfile)
	if err != nil {
		log.Fatalf("fail-closed: ключ: %v", err)
	}

	tun, ifname, err := openTUN(*tunName, *tunIP)
	if err != nil {
		log.Fatalf("fail-closed: TUN: %v", err)
	}
	log.Printf("TUN %s поднят с %s", ifname, *tunIP)

	// исходящее направление (я -> peer)
	outCfg := chaossync.GeomConfig{PortBase: *peerBase, PortCount: *peerCount, MinFrag: 200, MaxFrag: 1400, MinGapUs: 0, MaxGapUs: *maxGapUs, MinFlow: 1, MaxFlow: 12, Dir: *outDir}
	frag := chaossync.NewRotatingFragmenter(master, outCfg, *rotT, time.Now())
	// входящее направление (peer -> я): ТОТ ЖЕ тюнинг геометрии, что у отправителя
	inCfg := chaossync.GeomConfig{PortBase: *listenBase, PortCount: *listenCount, MinFrag: 200, MaxFrag: 1400, MinGapUs: 0, MaxGapUs: *maxGapUs, MinFlow: 1, MaxFlow: 12, Dir: *inDir}
	defrag := chaossync.NewRotatingDefragmenter(master, inCfg, *rotT, time.Now())

	datch := make(chan udpPkt, 8192)
	bound := 0
	var sharedSock *net.UDPConn
	for p := *listenBase; p < *listenBase+*listenCount; p++ {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: p})
		if err != nil {
			continue
		}
		bound++
		if p == *listenBase {
			sharedSock = conn // общий src-порт для fixsrc
		}
		go func(c *net.UDPConn) {
			buf := make([]byte, 2048)
			for {
				n, src, err := c.ReadFromUDP(buf)
					if err != nil {
						return
					}
					dat := make([]byte, n)
					copy(dat, buf[:n])
					datch <- udpPkt{dat, src}
				}
		}(conn)
	}
	if bound == 0 {
		log.Fatal("fail-closed: не слушаю ни один порт своего блока")
	}
	log.Printf("слушаю свой блок %d..%d (%d шт); исходящее -> %s блок %d..%d",
		*listenBase, *listenBase+*listenCount-1, bound, *peerHost, *peerBase, *peerBase+*peerCount-1)

	// логгер счётчиков
	go func() {
		tk := time.NewTicker(2 * time.Second)
		for range tk.C {
			log.Printf("стадии: tunRd=%d fragSent=%d udpRecv=%d ingestOK=%d tunWr=%d",
				cTunRead.Load(), cFragSent.Load(), cUdpRecv.Load(), cIngestOK.Load(), cTunWrite.Load())
		}
	}()

	// net -> tun
	go func() {
		for pkt := range datch {
			cUdpRecv.Add(1)
			defrag.TickEpoch(time.Now())
			if !defrag.Ingest(pkt.data) {
				continue
			}
			cIngestOK.Add(1)
			if pkt.src != nil {
				lastPeerIP.Store(pkt.src.IP.String()) // учим адрес клиента
			}
			for {
				p := defrag.Next()
				if p == nil {
					break
				}
				cTunWrite.Add(1)
				if _, err := tun.Write(p); err != nil {
					log.Printf("tun write: %v", err)
				}
			}
		}
	}()

	// tun -> net
	var conn *net.UDPConn
	sendFrag := func(wire []byte, g chaossync.PacketGeom) {
		target := *peerHost
		if v := lastPeerIP.Load(); v != nil {
			target = v.(string) // нода отвечает на выученный адрес клиента
		}
		if target == "" {
			return
		}
		dst, _ := net.ResolveUDPAddr("udp", net.JoinHostPort(target, itoa(g.DestPort)))
		if *fixsrc && sharedSock != nil {
			// клиент за NAT: фиксированный src-порт — NAT-дыра совпадает с портом приёма
			if _, err := sharedSock.WriteToUDP(wire, dst); err == nil {
				cFragSent.Add(1)
			}
		} else {
			if g.NewFlow || conn == nil {
				if conn != nil {
					conn.Close()
				}
				c, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
				if err != nil {
					return
				}
				conn = c
			}
			if _, err := conn.WriteToUDP(wire, dst); err == nil {
				cFragSent.Add(1)
			}
		}
		if g.GapUs > 0 {
			time.Sleep(time.Duration(g.GapUs) * time.Microsecond)
		}
	}

	buf := make([]byte, 2048)
	for {
		n, err := tun.Read(buf)
		if err != nil {
			log.Fatalf("tun read: %v", err)
		}
		cTunRead.Add(1)
		frag.TickEpoch(time.Now())
		frag.Push(buf[:n])
		// packet-aligned: один IP-пакет = один CDT-фрагмент (не режем пакет),
		// иначе дефрагментер отдавал бы куски и TUN отбрасывал бы обрезанный пакет.
		// Потерянный фрагмент = целый потерянный IP-пакет (чисто; TCP перешлёт).
		if wire, g, ok := frag.EmitFinal(); ok {
			sendFrag(wire, g)
		}
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
