// cdt-tun — TUN↔CDT мост: несёт настоящий IP-трафик через Chaos-Dispersed
// Transport. Симметричный двусторонний мост. Направления разделены (Dir),
// чтобы не было повтора nonce. Счётчики стадий — для отладки/метрик.
package main

import (
	"encoding/binary"
	"flag"
	"log"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"chameleon/internal/chaossync"
)

const (
	iffTUN    = 0x0001
	iffNoPI   = 0x1000
	tunsetiff = 0x400454ca
)

// счётчики стадий моста (отладка/метрики)
var (
	cTunRead  atomic.Uint64 // прочитано IP-пакетов из TUN
	cFragSent atomic.Uint64 // отправлено фрагментов в peer
	cUdpRecv  atomic.Uint64 // принято UDP-датаграмм из peer
	cIngestOK atomic.Uint64 // опознано фрагментов (AEAD+nonce сошлись)
	cTunWrite atomic.Uint64 // записано IP-пакетов в TUN
)

// udpPkt — датаграмма + адрес отправителя.
type udpPkt struct {
	data []byte
	src  *net.UDPAddr
}

// lastPeerIP — адрес клиента от ВАЛИДНЫХ (расшифрованных) фрагментов. Нода отвечает ему;
// учится не от шума сканеров, а от прошедших AEAD фрагментов.
var lastPeerIP atomic.Value // string

const (
	siocgifflags  = 0x8913
	socsifflags   = 0x8914
	socsifaddr    = 0x8916
	socsifmtu     = 0x8922
	socsifnetmask = 0x891c
	iffUp         = 0x1
	iffRunning    = 0x40
)

// ifreqIoctl — ifreq-ioctl на контрольном сокете (без внешних бинарей ip/sysctl).
func ifreqIoctl(name string, cmd uintptr, setup func(*[40]byte)) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	var ifr [40]byte
	copy(ifr[:16], name)
	setup(&ifr)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), cmd, uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return errno
	}
	return nil
}

// configIface — поднять интерфейс + адрес + MTU чистым ioctl. Самодостаточно:
// работает в минимальных окружениях (контейнер без iproute2) и ложится в основу
// Windows-варианта (там тоже нет `ip`).
func configIface(name, ipCIDR string, mtu int) error {
	ip, ipnet, err := net.ParseCIDR(ipCIDR)
	if err != nil {
		return err
	}
	if err := ifreqIoctl(name, socsifmtu, func(ifr *[40]byte) {
		binary.LittleEndian.PutUint32(ifr[16:20], uint32(mtu))
	}); err != nil {
		return err
	}
	if err := ifreqIoctl(name, socsifaddr, func(ifr *[40]byte) {
		binary.LittleEndian.PutUint16(ifr[16:18], syscall.AF_INET)
		copy(ifr[20:24], ip.To4())
	}); err != nil {
		return err
	}
	if err := ifreqIoctl(name, socsifnetmask, func(ifr *[40]byte) {
		binary.LittleEndian.PutUint16(ifr[16:18], syscall.AF_INET)
		copy(ifr[20:24], ipnet.Mask)
	}); err != nil {
		return err
	}
	if err := ifreqIoctl(name, socsifflags, func(ifr *[40]byte) {
		binary.LittleEndian.PutUint16(ifr[16:18], iffUp|iffRunning)
	}); err != nil {
		return err
	}
	return nil
}

// openTUN — создать TUN (Linux, raw IP без PI-заголовка) и настроить без
// внешних команд: MTU/адрес/поднятие через ioctl, IPv6-шум глушим через /proc.
func openTUN(name, ipCIDR string) (*os.File, string, error) {
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		return nil, "", err
	}
	var ifr [40]byte
	copy(ifr[:16], name)
	binary.LittleEndian.PutUint16(ifr[16:18], iffTUN|iffNoPI)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), tunsetiff, uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		syscall.Close(fd)
		return nil, "", errno
	}
	in := name
	if z := indexByte(ifr[:16], 0); z >= 0 {
		in = string(ifr[:z])
	}
	f := os.NewFile(uintptr(fd), "tun")
	// глушим IPv6-RS шум на старте через /proc (иначе стартовые фрагменты,
	// потерянные до поднятия peer, дадут дыру в seq; gap-skip ловит большие дыры,
	// но малый стартовый шум проще не порождать)
	os.WriteFile("/proc/sys/net/ipv6/conf/"+in+"/disable_ipv6", []byte("1"), 0644)
	if err := configIface(in, ipCIDR, 1300); err != nil { // MTU 1300: пакет целиком в один CDT-фрагмент
		syscall.Close(fd)
		return nil, "", err
	}
	return f, in, nil
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

func main() {
	keyfile := flag.String("keyfile", "cdt.key", "файл мастер-ключа (0600)")
	tunIP := flag.String("tunip", "", "мой туннельный IP/CIDR (обязателен)")
	peerHost := flag.String("peerhost", "", "реальный IP peer'а для отправки (обязателен)")
	listenBase := flag.Int("listenbase", 23000, "первый порт МОЕГО блока (приём)")
	listenCount := flag.Int("listencount", 48, "число портов моего блока")
	peerBase := flag.Int("peerbase", 20000, "первый порт блока PEER'а (куда шлю)")
	peerCount := flag.Int("peercount", 48, "число портов блока peer'а")
	outDir := flag.String("outdir", "c2n", "Dir исходящего направления")
	inDir := flag.String("indir", "n2c", "Dir входящего направления")
	rotT := flag.Uint64("T", 8, "период ротации геометрии/ключа, сек")
	maxGapUs := flag.Int("maxgap", 150, "макс. межпакетный интервал, мкс")
	fixsrc := flag.Bool("fixsrc", false, "клиент за NAT: фиксированный src-порт (=порту прослушивания), чтобы NAT-дыра совпадала")
	flag.Parse()

	log.SetPrefix("[cdt-tun] ")
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if *tunIP == "" || *peerHost == "" {
		log.Fatal("нужны -tunip и -peerhost")
	}
	master, err := chaossync.LoadMasterKey(*keyfile)
	if err != nil {
		log.Fatalf("fail-closed: ключ: %v", err)
	}

	tun, ifname, err := openTUN("cdt0", *tunIP)
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
		tk := time.NewTicker(1 * time.Second)
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
				lastPeerIP.Store(pkt.src.IP.String()) // учим адрес клиента по валидному фрагменту
			}
			for {
				pkt := defrag.Next()
				if pkt == nil {
					break
				}
				cTunWrite.Add(1)
				if _, err := tun.Write(pkt); err != nil {
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
		dst, _ := net.ResolveUDPAddr("udp", net.JoinHostPort(target, itoa(g.DestPort)))
		if *fixsrc && sharedSock != nil {
			// клиент за NAT: фиксированный src-порт (=порту прослушивания) — NAT-дыра совпадает
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
		// packet-aligned: один IP-пакет = один CDT-фрагмент (не режем пакет на части),
		// иначе дефрагментер отдавал бы куски и TUN отбрасывал бы обрезанный пакет.
		// Потерянный фрагмент = целый потерянный IP-пакет (чисто; верхние слои перешлют).
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
