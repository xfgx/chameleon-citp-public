// cdt-socks — VPN-клиент: SOCKS5-прокси поверх надёжного потока CDT.
// Это и есть Windows-клиент выхода на зарубежную ноду (не нужен TUN/админ —
// userspace SOCKS5; браузер/система указывают прокси). Нода (зарубежная/RU для
// теста) принимает поток и делает connect-out к целям в свободный интернет.
//
// Транспорт = надёжный упорядоченный поток поверх CDT-дисперсии (cdtstream:
// retransmit+ACK). Маскировка (несвязуемая дисперсия геометрии, AEAD, ротация
// эпох) — из проверенного ядра CDT. Направления разделены (Dir).
//
// Мультиплексирование поверх ОДНОГО надёжного потока: кадр
//
//	[streamID(4)][type(1)][len(2)][payload]
//
// type: 0=OPEN(payload "host:port"), 1=DATA, 2=CLOSE, 3=OPENOK, 4=OPENFAIL.
// (v1: общий надёжный поток -> head-of-line при потере; при 1.5% потерь редко.)
package main

import (
	"encoding/binary"
	"flag"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"chameleon/internal/chaossync"
)

const (
	ftOpen    = 0
	ftData    = 1
	ftClose   = 2
	ftOpenOK  = 3
	ftOpenErr = 4
	frameHdr  = 7
	frameMax  = 1100
)

var (
	cUp, cDown, cDrop atomic.Uint64
	lastPeer          atomic.Value // *net.UDPAddr — выученный полный адрес клиента (нода)
	lastSock          atomic.Value // *net.UDPConn — сокет блока, с которого пришло (NAT-дыра)
)

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

// ---------- кадрирование поверх надёжного потока ----------

type mux struct {
	st      *chaossync.Stream
	wrMu    sync.Mutex // сериализация кадров (иначе Write одного кадра переплетётся с другим)
	recvBuf []byte
	mu      sync.Mutex
	conns   map[uint32]*connState
}

type connState struct {
	id     uint32
	in     chan []byte // входящие DATA для этого соединения
	opened chan bool   // OPENOK/OPENFAIL
	target string
}

func newMux(st *chaossync.Stream) *mux {
	return &mux{st: st, conns: map[uint32]*connState{}}
}

// sendFrame — записать кадр в надёжный поток (атомарно по кадру).
func (m *mux) sendFrame(typ byte, id uint32, payload []byte) {
	f := make([]byte, frameHdr+len(payload))
	binary.BigEndian.PutUint32(f, id)
	f[4] = typ
	binary.BigEndian.PutUint16(f[5:], uint16(len(payload)))
	copy(f[frameHdr:], payload)
	m.wrMu.Lock()
	m.st.Write(f)
	m.wrMu.Unlock()
}

// pump — разобрать входящие байты потока на кадры и развести по соединениям.
func (m *mux) pump() {
	for {
		if msg := m.st.Read(); msg != nil {
			m.mu.Lock()
			m.recvBuf = append(m.recvBuf, msg...)
			m.deframeLocked()
			m.mu.Unlock()
		} else {
			time.Sleep(2 * time.Millisecond)
		}
	}
}

func (m *mux) deframeLocked() {
	for len(m.recvBuf) >= frameHdr {
		id := binary.BigEndian.Uint32(m.recvBuf)
		typ := m.recvBuf[4]
		ln := int(binary.BigEndian.Uint16(m.recvBuf[5:]))
		if len(m.recvBuf) < frameHdr+ln {
			return
		}
		payload := m.recvBuf[frameHdr : frameHdr+ln]
		m.recvBuf = m.recvBuf[frameHdr+ln:]
		m.route(typ, id, payload)
	}
}

func (m *mux) route(typ byte, id uint32, payload []byte) {
	cs, ok := m.conns[id]
	if !ok {
		// новое соединение (нода): OPEN с целью
		if typ == ftOpen {
			cs = &connState{id: id, in: make(chan []byte, 256), opened: make(chan bool, 1), target: string(payload)}
			m.conns[id] = cs
			go nodeServe(m, cs)
		}
		return
	}
	switch typ {
	case ftData:
		cDown.Add(1)
		select {
		case cs.in <- payload:
		default:
			cs.in <- payload // backpressure
		}
	case ftOpenOK:
		select {
		case cs.opened <- true:
		default:
		}
	case ftOpenErr:
		select {
		case cs.opened <- false:
		default:
		}
	case ftClose:
		close(cs.in)
		delete(m.conns, id)
	}
}

// ---------- CDT-канал (networking + надёжный поток) ----------

func main() {
	isNode := flag.Bool("node", false, "режим ноды (connect-out в интернет)")
	keyfile := flag.String("keyfile", "cdt.key", "файл мастер-ключа (0600)")
	genkey := flag.Bool("genkey", false, "создать мастер-ключ и выйти")
	peerIP := flag.String("peer", "", "IP ноды (клиенту)")
	socksAddr := flag.String("socks", "127.0.0.1:1080", "локальный SOCKS5 listen (клиент)")
	c2nBase := flag.Int("c2nbase", 20000, "база блока портов ноды (клиент->нода)")
	c2nCount := flag.Int("c2ncount", 48, "число портов блока ноды")
	n2cPort := flag.Int("n2cport", 23500, "порт прослушивания клиента (нода->клиент)")
	rotT := flag.Uint64("T", 8, "период ротации, сек")
	maxGap := flag.Int("maxgap", 100, "макс межпакетный интервал, мкс")
	geomauto := flag.Bool("geomauto", false, "автопилот дисперсии CDT (класс по риску, переключение на границах эпох)")
	flag.Parse()
	log.SetPrefix("[cdt-socks] ")
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if *genkey {
		if err := chaossync.GenerateMasterKey(*keyfile); err != nil {
			log.Fatalf("genkey: %v", err)
		}
		log.Printf("ключ создан: %s", *keyfile)
		return
	}
	master, err := chaossync.LoadMasterKey(*keyfile)
	if err != nil {
		log.Fatalf("fail-closed: ключ: %v", err)
	}

	// геометрия направлений (общая для обеих сторон)
	tuning := func() chaossync.GeomConfig {
		return chaossync.GeomConfig{MinFrag: 200, MaxFrag: 1400, MinGapUs: 0, MaxGapUs: *maxGap, MinFlow: 1, MaxFlow: 12}
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
	listenEff := listenCount
	if *geomauto && listenEff > 1 && listenEff < 512 {
		listenEff = 512 // конверт автопилота: слушаем максимальную ширину класса 3
	}

	// сеть: слушаем свой блок; отправка — через send callback надёжного потока
	type inPkt struct {
		data []byte
		src  *net.UDPAddr
		sock *net.UDPConn
	}
	datch := make(chan inPkt, 8192)
	var sharedSock *net.UDPConn
	for p := listenBase; p < listenBase+listenEff; p++ {
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

	// send callback надёжного потока -> дисперсия по сети
	sendWire := func(wire []byte, g chaossync.PacketGeom) {
		var dst *net.UDPAddr
		if *isNode {
			v := lastPeer.Load()
			if v == nil {
				return
			}
			dst = v.(*net.UDPAddr) // нода отвечает на полный выученный адрес клиента (NAT-дыра)
		} else {
			dst, _ = net.ResolveUDPAddr("udp", net.JoinHostPort(*peerIP, itoa(g.DestPort)))
		}
		if *isNode {
			if sv := lastSock.Load(); sv != nil {
				if _, err := sv.(*net.UDPConn).WriteToUDP(wire, dst); err == nil {
					cUp.Add(1)
				}
				return
			}
			return
		}
		// клиент за NAT: стабильный src-порт (sharedSock) чтобы NAT-дыра совпадала
		if _, err := sharedSock.WriteToUDP(wire, dst); err == nil {
			cUp.Add(1)
		}
		if g.GapUs > 0 {
			time.Sleep(time.Duration(g.GapUs) * time.Microsecond)
		}
	}

	st := chaossync.NewStream(master, outCfg, inCfg, *rotT, sendWire)
	if *geomauto {
		st.EnableGeomAutopilot(chaossync.NewClassStepper(0, 2), outCfg, inCfg)
		log.Printf("автопилот дисперсии включён (классы 0..%d, конверт приёма %d портов)", chaossync.GeomClasses-1, listenEff)
	}

	// сетевой приём -> надёжный поток
	go func() {
		for pkt := range datch {
			st.HandlePacket(pkt.data)
			if pkt.src != nil {
				lastPeer.Store(pkt.src)
				lastSock.Store(pkt.sock)
			}
		}
	}()
	// тикер retransmit + ротация
	go func() {
		tk := time.NewTicker(15 * time.Millisecond)
		for range tk.C {
			st.Tick()
		}
	}()

	mx := newMux(st)
	go mx.pump()

	if *isNode {
		log.Printf("нода: блок %d..%d, connect-out в интернет", listenBase, listenBase+listenCount-1)
		select {}
	}
	// клиент: локальный SOCKS5
	ln, err := net.Listen("tcp", *socksAddr)
	if err != nil {
		log.Fatalf("fail-closed: SOCKS5 listen: %v", err)
	}
	log.Printf("клиент: SOCKS5 на %s -> нода %s блок %d..%d (дисперсия); укажи этот SOCKS5 в браузере/системе", *socksAddr, *peerIP, *c2nBase, *c2nBase+*c2nCount-1)
	var nextID uint32 = 1
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		id := atomic.AddUint32(&nextID, 1)
		go clientServe(mx, c, id)
	}
}

// ---------- SOCKS5 client side ----------

func clientServe(mx *mux, app net.Conn, id uint32) {
	defer app.Close()
	// greeting
	buf := make([]byte, 262)
	if _, err := io.ReadFull(app, buf[:2]); err != nil {
		return
	}
	nm := int(buf[1])
	if _, err := io.ReadFull(app, buf[:nm]); err != nil {
		return
	}
	if _, err := app.Write([]byte{5, 0}); err != nil {
		return
	} // no auth
	// CONNECT request
	if _, err := io.ReadFull(app, buf[:4]); err != nil {
		return
	}
	if buf[0] != 5 || buf[1] != 1 {
		return
	} // только CONNECT
	atyp := buf[3]
	var host string
	switch atyp {
	case 1: // IPv4
		if _, err := io.ReadFull(app, buf[:4]); err != nil {
			return
		}
		host = net.IP(buf[:4]).String()
	case 3: // domain
		if _, err := io.ReadFull(app, buf[:1]); err != nil {
			return
		}
		l := int(buf[0])
		if _, err := io.ReadFull(app, buf[:l]); err != nil {
			return
		}
		host = string(buf[:l])
	case 4: // IPv6
		if _, err := io.ReadFull(app, buf[:16]); err != nil {
			return
		}
		host = net.IP(buf[:16]).String()
	default:
		return
	}
	if _, err := io.ReadFull(app, buf[:2]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(buf[:2])
	target := net.JoinHostPort(host, itoa(int(port)))

	cs := &connState{id: id, in: make(chan []byte, 256), opened: make(chan bool, 1)}
	mx.mu.Lock()
	mx.conns[id] = cs
	mx.mu.Unlock()
	mx.sendFrame(ftOpen, id, []byte(target))
	ok := <-cs.opened
	if !ok {
		app.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0}) // failure
		return
	}
	app.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}) // success
	log.Printf("SOCKS5 CONNECT %s (stream %d) — открыто через CDT", target, id)

	// app -> нода
	go func() {
		b := make([]byte, frameMax)
		for {
			n, err := app.Read(b)
			if n > 0 {
				mx.sendFrame(ftData, id, b[:n])
				cUp.Add(1)
			}
			if err != nil {
				mx.sendFrame(ftClose, id, nil)
				return
			}
		}
	}()
	// нода -> app
	for chunk := range cs.in {
		if _, err := app.Write(chunk); err != nil {
			return
		}
	}
}

// ---------- node side ----------

func nodeServe(mx *mux, cs *connState) {
	target, err := net.DialTimeout("tcp", cs.target, 15*time.Second)
	if err != nil {
		log.Printf("нода: connect %s: %v", cs.target, err)
		mx.sendFrame(ftOpenErr, cs.id, nil)
		return
	}
	mx.sendFrame(ftOpenOK, cs.id, nil)
	log.Printf("нода: CONNECT %s (stream %d) открыт", cs.target, cs.id)
	defer target.Close()
	defer func() { mx.mu.Lock(); delete(mx.conns, cs.id); mx.mu.Unlock() }()
	// target -> клиент
	go func() {
		b := make([]byte, frameMax)
		for {
			n, err := target.Read(b)
			if n > 0 {
				mx.sendFrame(ftData, cs.id, b[:n])
			}
			if err != nil {
				mx.sendFrame(ftClose, cs.id, nil)
				return
			}
		}
	}()
	// клиент -> target
	for chunk := range cs.in {
		if _, err := target.Write(chunk); err != nil {
			return
		}
	}
}
