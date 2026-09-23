// ks-vpn — TUN↔KS мост: data-plane на keystream-инверсии ядра chaossync.
//
// Wire: headerless UDP-датаграммы nonce‖ct, по одному порту на направление.
// Потеря датаграммы = потерянный IP-пакет (TCP выше перешлёт): состояние
// решётки не рвётся — она шагает по счётчику, не по прибытию. Ротация эпох
// бесплатная (общий счётчик времени, без in-band налога).
//
// Probe-invisible: отвечаем только на AEAD-валидные датаграммы, всё прочее
// (включая активные пробы) — ноль ответа; адрес клиента нода учит только от
// валидных датаграмм (не от шума сканеров).
//
// Надёжность: мост несёт СЫРОЙ IP; внутренний TCP приложений надёжен
// end-to-end. Платформенно-зависима только TUN-часть (tun_linux.go —
// переиспользована из cdt-vpn без изменений; tun_windows.go — Wintun).
package main

import (
	"flag"
	"log"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"chameleon/internal/chaossync"
)

// счётчики стадий моста (отладка/метрики)
var (
	cTunRead  atomic.Uint64 // IP-пакетов прочитано из TUN
	cSent     atomic.Uint64 // датаграмм запечатано и отправлено
	cUdpRecv  atomic.Uint64 // UDP-датаграмм принято с провода
	cIngestOK atomic.Uint64 // прошли AEAD (валидные)
	cDropped  atomic.Uint64 // шум/чужие/повторы — молча отброшено
	cTunWrite atomic.Uint64 // IP-пакетов записано в TUN
)

// lastPeer — адрес клиента, выученный от ВАЛИДНЫХ (расшифрованных) датаграмм.
// Нода отвечает ему; учится не от шума, а после AEAD.
var lastPeer atomic.Value // *net.UDPAddr

type inPkt struct {
	data []byte
	src  *net.UDPAddr
}

func main() {
	keyfile := flag.String("keyfile", "ks-vpn.key", "файл мастер-ключа (0600)")
	genkey := flag.Bool("genkey", false, "создать мастер-ключ (0600) и выйти")
	tunName := flag.String("tun", "ks0", "имя TUN-адаптера")
	tunIP := flag.String("tunip", "", "мой туннельный IP/CIDR (обязателен)")
	peerHost := flag.String("peerhost", "", "IP ноды (обязателен на клиенте; на ноде пусто — учится)")
	listenPort := flag.Int("listen", 24001, "мой UDP-порт приёма")
	peerPort := flag.Int("peerport", 24000, "UDP-порт приёма peer'а")
	outDir := flag.String("outdir", "c2n", "Dir исходящего направления")
	inDir := flag.String("indir", "n2c", "Dir входящего направления")
	rotT := flag.Uint64("T", 8, "период ротации эпох, сек (одинаковый на обеих сторонах)")
	flag.Parse()

	log.SetPrefix("[ks-vpn] ")
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

	// keystream-концы направлений (общий счётчик эпох на обеих сторонах)
	tx := chaossync.NewRotatingSender(master, *outDir, *rotT, time.Now())
	rx := chaossync.NewRotatingReceiver(master, *inDir, *rotT, time.Now())

	// сеть: один сокет приёма; отправка — с того же сокета (NAT-дыра совпадает)
	sock, err := net.ListenUDP("udp", &net.UDPAddr{Port: *listenPort})
	if err != nil {
		log.Fatalf("fail-closed: слушатель UDP :%d: %v", *listenPort, err)
	}
	log.Printf("слушаю UDP :%d; исходящее -> %s:%d", *listenPort, *peerHost, *peerPort)

	// логгер счётчиков
	go func() {
		tk := time.NewTicker(2 * time.Second)
		for range tk.C {
			log.Printf("стадии: tunRd=%d sent=%d udpRecv=%d ingestOK=%d dropped=%d tunWr=%d",
				cTunRead.Load(), cSent.Load(), cUdpRecv.Load(), cIngestOK.Load(), cDropped.Load(), cTunWrite.Load())
		}
	}()

	datch := make(chan inPkt, 8192)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, src, err := sock.ReadFromUDP(buf)
			if err != nil {
				return
			}
			d := make([]byte, n)
			copy(d, buf[:n])
			datch <- inPkt{d, src}
		}
	}()

	// net -> tun
	go func() {
		for pkt := range datch {
			cUdpRecv.Add(1)
			rx.TickEpoch(time.Now())
			plain, ok := rx.Ingest(pkt.data)
			if !ok {
				cDropped.Add(1) // probe-invisibility: молчим
				continue
			}
			cIngestOK.Add(1)
			if pkt.src != nil {
				lastPeer.Store(pkt.src) // учим адрес только от валидных датаграмм
			}
			cTunWrite.Add(1)
			if _, err := tun.Write(plain); err != nil {
				log.Printf("tun write: %v", err)
			}
		}
	}()

	// tun -> net
	buf := make([]byte, 2048)
	for {
		n, err := tun.Read(buf)
		if err != nil {
			log.Fatalf("tun read: %v", err)
		}
		cTunRead.Add(1)
		tx.TickEpoch(time.Now())
		// packet-aligned: один IP-пакет = одна KS-датаграмма.
		wire := tx.Seal(buf[:n])
		dst := peerAddr(*peerHost, *peerPort)
		if dst == nil {
			continue // нода ещё не знает клиента — отбросить (TCP выше перешлёт)
		}
		if _, err := sock.WriteToUDP(wire, dst); err == nil {
			cSent.Add(1)
		}
	}
}

// peerAddr — куда слать: выученный от валидных датаграмм адрес приоритетнее
// (нода), иначе сконфигурированный peerhost (клиент до первого ответа).
func peerAddr(host string, port int) *net.UDPAddr {
	if v := lastPeer.Load(); v != nil {
		return v.(*net.UDPAddr)
	}
	if host == "" {
		return nil
	}
	a, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil
	}
	return a
}
