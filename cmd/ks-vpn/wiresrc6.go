package main

// wiresrc6.go — пул СЛУЧАЙНЫХ ИСХОДНЫХ v6-адресов клиентского провода.
//
// Задача (ТЗ владельца 2026-09-04): каждая KS-датаграмма должна уходить со
// случайного адреса клиента на случайный адрес пула ноды. Случайное
// НАЗНАЧЕНИЕ делает wirev6.go (nextDst), случайный ИСТОЧНИК — этот файл.
//
// Почему набор сокетов, а не «адрес на пакет» напрямую: задать источник
// v6-датаграммы на лету можно только через IPV6_PKTINFO на отправке, а в
// x/net/ipv6 на windows/amd64 это не реализовано (клиентский лог полевого
// прогона: "pktinfo FlagDst: not implemented on windows/amd64"). Поэтому
// источник задаётся единственным доступным способом — bind сокета на нужный
// адрес. Назначение адреса на адаптер стоит десятки миллисекунд, поэтому
// держим N адресов одновременно, каждый со своим сокетом, и выбираем сокет
// СЛУЧАЙНО НА КАЖДУЮ ДАТАГРАММУ; сам набор целиком переезжает по таймеру.
// Итог на проводе: соседние датаграммы идут с разных адресов на разные
// адреса, привязки «один клиент = один IP» нет.
//
// Честные границы: мгновенная энтропия источника = N адресов (по умолчанию
// 16), а не 2^64 на пакет; полная смена набора — каждые -wire6rot секунд.
// Требуется нативный v6-префикс шире /128 (обычно /64 от провайдера); нет
// такого — честная ошибка, провод работает с одним исходным адресом.

import (
	"crypto/rand"
	"errors"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var (
	errNoNativeV6   = errors.New("wire6src: нативный глобальный IPv6-префикс не найден")
	errSrcTooNarrow = errors.New("wire6src: нативный префикс /128 — ротировать источник нечем")
	errSrcNoSocks   = errors.New("wire6src: ни один исходный адрес не удалось поднять")
)

// srcMaxAddrs — потолок набора (адаптер не должен обрастать сотнями адресов).
const srcMaxAddrs = 64

// srcGrace — сколько держать прежний набор открытым после переезда: ответы на
// уже отправленные датаграммы приходят на прежние адреса.
const srcGrace = 5 * time.Second

// srcMgr6 — платформенный способ получить сокет, привязанный к конкретному
// исходному адресу. Windows: назначить /128 на нативный адаптер и bind.
// Linux: bind с IPV6_FREEBIND (адрес назначать не требуется).
type srcMgr6 interface {
	// Detect — нативный глобальный префикс клиента (обычно /64).
	Detect(tunIfname string) (*net.IPNet, error)
	// Listen — сокет на случайном свободном порту с исходным адресом ip.
	Listen(ip net.IP) (*net.UDPConn, error)
	// Release — снять адрес (если платформа его назначала).
	Release(ip net.IP)
}

// srcPool6 — живой набор исходных адресов со своими сокетами.
type srcPool6 struct {
	mgr    srcMgr6
	prefix *net.IPNet
	n      int
	period time.Duration
	datch  chan<- inPkt

	mu    sync.Mutex
	socks []*net.UDPConn
	addrs []net.IP

	hook atomic.Value // func() — уведомление о приёме (watchdog провода)
	stop chan struct{}
}

// newSrcPool6 — spec: "auto" (определить нативный префикс) либо явный CIDR.
func newSrcPool6(spec, tunIfname string, n int, rotSec uint64, datch chan<- inPkt) (*srcPool6, error) {
	mgr := newSrcMgr6()
	var prefix *net.IPNet
	if spec == "auto" {
		p, err := mgr.Detect(tunIfname)
		if err != nil {
			return nil, err
		}
		prefix = p
	} else {
		_, p, err := net.ParseCIDR(spec)
		if err != nil {
			return nil, err
		}
		if p.IP.To4() != nil || p.IP.To16() == nil {
			return nil, errV6BadPrefix
		}
		prefix = p
	}
	if ones, bits := prefix.Mask.Size(); bits != 128 || ones >= 128 {
		return nil, errSrcTooNarrow
	}
	if n < 1 {
		n = 1
	}
	if n > srcMaxAddrs {
		n = srcMaxAddrs
	}
	if rotSec < 5 {
		rotSec = 5 // чаще смысла нет: переезд набора платный (назначение адресов)
	}
	s := &srcPool6{
		mgr: mgr, prefix: prefix, n: n,
		period: time.Duration(rotSec) * time.Second,
		datch:  datch, stop: make(chan struct{}),
	}
	if err := s.refresh(); err != nil {
		return nil, err
	}
	go s.refreshLoop()
	log.Printf("wire6src: исходные адреса — случайные из %s, %d одновременно, переезд набора каждые %s", prefix, n, s.period)
	return s, nil
}

// refresh — поднять новый набор адресов+сокетов и заменить прежний.
func (s *srcPool6) refresh() error {
	socks := make([]*net.UDPConn, 0, s.n)
	addrs := make([]net.IP, 0, s.n)
	var lastErr error
	for i := 0; i < s.n; i++ {
		ip, err := randV6(s.prefix)
		if err != nil {
			lastErr = err
			continue
		}
		sock, err := s.mgr.Listen(ip)
		if err != nil {
			lastErr = err
			s.mgr.Release(ip)
			continue
		}
		socks = append(socks, sock)
		addrs = append(addrs, ip)
		go s.reader(sock)
	}
	if len(socks) == 0 {
		if lastErr != nil {
			return lastErr
		}
		return errSrcNoSocks
	}
	s.mu.Lock()
	oldSocks, oldAddrs := s.socks, s.addrs
	s.socks, s.addrs = socks, addrs
	s.mu.Unlock()
	if len(socks) < s.n {
		log.Printf("wire6src: поднято %d/%d исходных адресов (последняя ошибка: %v)", len(socks), s.n, lastErr)
	}
	if len(oldSocks) > 0 {
		go s.retire(oldSocks, oldAddrs)
	}
	return nil
}

// retire — прежний набор доживает окно srcGrace (ловит ответы), затем снос.
func (s *srcPool6) retire(socks []*net.UDPConn, addrs []net.IP) {
	tm := time.NewTimer(srcGrace)
	defer tm.Stop()
	select {
	case <-s.stop:
	case <-tm.C:
	}
	for _, c := range socks {
		c.Close()
	}
	for _, a := range addrs {
		s.mgr.Release(a)
	}
}

func (s *srcPool6) refreshLoop() {
	tk := time.NewTicker(s.period)
	defer tk.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-tk.C:
			if err := s.refresh(); err != nil {
				log.Printf("wire6src: переезд набора не удался: %v (работаем прежним набором)", err)
			}
		}
	}
}

// reader — приём ответов на конкретный исходный адрес.
func (s *srcPool6) reader(sock *net.UDPConn) {
	buf := make([]byte, 2048)
	for {
		n, src, err := sock.ReadFromUDP(buf)
		if err != nil {
			return // сокет закрыт при переезде/остановке — штатно
		}
		d := make([]byte, n)
		copy(d, buf[:n])
		if f, ok := s.hook.Load().(func()); ok && f != nil {
			f()
		}
		s.datch <- inPkt{data: d, src: src}
	}
}

// setHook — уведомление провода о приёме (снимает watchdog «тишины»).
func (s *srcPool6) setHook(f func()) { s.hook.Store(f) }

// pick — случайный сокет набора: источник очередной датаграммы.
func (s *srcPool6) pick() *net.UDPConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.socks) == 0 {
		return nil
	}
	return s.socks[randIdx(len(s.socks))]
}

// cur — текущий набор адресов строкой (для лога стадий).
func (s *srcPool6) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.socks)
}

func (s *srcPool6) close() {
	close(s.stop)
	s.mu.Lock()
	socks, addrs := s.socks, s.addrs
	s.socks, s.addrs = nil, nil
	s.mu.Unlock()
	for _, c := range socks {
		c.Close()
	}
	for _, a := range addrs {
		s.mgr.Release(a)
	}
	log.Printf("wire6src: исходные адреса сняты")
}

// randIdx — равномерный индекс 0..n-1 на crypto/rand (без math/rand в
// data-plane: единый источник случайности во всём проекте).
func randIdx(n int) int {
	if n <= 1 {
		return 0
	}
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return int(uint16(b[0])<<8|uint16(b[1])) % n
}
