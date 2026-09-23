package main

// wirev6.go — клиентский v6-ПРОВОД: КАЖДАЯ KS-датаграмма уходит СО
// СЛУЧАЙНОГО исходного адреса клиента НА СЛУЧАЙНЫЙ адрес routed-пула
// ноды (ТЗ владельца 2026-09-04).
//
// Назначение (nextDst): случайный адрес из /48 ноды на каждый пакет.
// Брокер заворачивает весь пул на ноду (проверено внешним прогоном
// 2026-09-04: случайные адреса 5b4a:*::* ответили 3/3), нода держит пул
// локальным (anyip) и отвечает ровно с адреса, на который пришла
// датаграмма (IPv6 pktinfo).
//
// Источник (wiresrc6.go): случайный адрес из нативного префикса клиента
// на каждый пакет (выбор из набора предназначенных сокетов; причина
// именно набора — нет IPV6_PKTINFO на отправке на windows/amd64).
// Без -wire6src источник один (стек выбирает сам), порт — случайный.
//
// Откат по ПРИЁМУ, а не по ошибкам отправки (урок полевого прогона
// 2026-09-04): провайдер может МОЛЧА терять v6-датаграммы — WriteTo возвращал
// успех на ~1300 отправках, а нода не приняла ни одной, и порог по
// ошибкам не срабатывал (тишина вместо трафика). Теперь: нет ответов по
// v6 за wire6SilenceSec при реальной отправке — честный откат на v4-провод,
// повторная проба через wire6RetryDownSec; возврат — только по факту приёма.
//
// Этическая граница без изменений: свой трафик, свой делегированный пул.

import (
	"errors"
	"log"
	"net"
	"sync/atomic"
	"time"
)

var errWire6Down = errors.New("wire6: v6-провод недоступен (откат на v4)")

const (
	// wireFailsToFallback — подряд ошибок отправки (явный ENETUNREACH:
	// нативного v6 нет вовсе) — быстрый откат без ожидания окна тишины.
	wireFailsToFallback = 5
	// wire6SilenceSec — окно тишины: шлём, а ответов по v6 нет.
	wire6SilenceSec = 12
	// wire6MinSentToTrip — сколько датаграмм надо реально отправить, чтобы
	// тишина считалась доказанной (иначе простой канал = ложный откат).
	wire6MinSentToTrip = 20
	// wire6RetryDownSec — как часто перепробовать v6-провод после отката.
	wire6RetryDownSec = 60
)

type wireV6 struct {
	pool   *net.IPNet
	port   int
	rotSec uint64
	src    *srcPool6 // пул случайных ИСХОДНЫХ адресов (nil = источник один)

	cur       atomic.Value  // *net.UDPConn — сокет без пула источников (случайный порт)
	ok        atomic.Bool   // v6-провод жив; иначе вызывающий ходит по v4
	fails     atomic.Uint64 // подряд ошибок отправки
	lastRx    atomic.Int64  // unix-время последнего приёма по v6-проводу
	sentSince atomic.Uint64 // отправлено с последнего приёма
	downAt    atomic.Int64  // когда ушли в откат
	stop      chan struct{}
	datch     chan<- inPkt // общий с v4 канал приёма
}

// newWireV6 — пул назначения + (опционально) пул источников. Без пула
// источников поднимается один сокет на случайном свободном порту.
func newWireV6(poolCIDR string, port int, rotSec uint64, datch chan<- inPkt, src *srcPool6) (*wireV6, error) {
	_, pool, err := net.ParseCIDR(poolCIDR)
	if err != nil {
		return nil, err
	}
	if pool.IP.To4() != nil || pool.IP.To16() == nil {
		return nil, errV6BadPrefix
	}
	w := &wireV6{pool: pool, port: port, rotSec: rotSec, src: src, stop: make(chan struct{}), datch: datch}
	w.ok.Store(true)
	w.lastRx.Store(time.Now().Unix()) // окно тишины считается от старта
	if src != nil {
		src.setHook(w.onRx)
		log.Printf("wire6: источник — случайный адрес из набора (%d шт.) на КАЖДЫЙ пакет; цели — случайные адреса %s, порт %d", src.count(), w.pool, w.port)
	} else if err := w.rebind(); err != nil {
		return nil, err
	}
	if src == nil {
		go w.rebindLoop()
	}
	go w.watchdog()
	return w, nil
}

// rebind — новый сокет на случайном свободном порту (режим без пула
// источников). Старый закрывается, его reader штатно завершается.
func (w *wireV6) rebind() error {
	ls, err := net.ListenUDP("udp6", nil)
	if err != nil {
		return err
	}
	old := w.cur.Swap(ls)
	if old != nil {
		old.(*net.UDPConn).Close()
	}
	la, _ := ls.LocalAddr().(*net.UDPAddr)
	log.Printf("wire6: исходный порт %d (случайный свободный); цели — случайные адреса %s, порт %d", la.Port, w.pool, w.port)
	go w.reader(ls)
	return nil
}

func (w *wireV6) reader(ls *net.UDPConn) {
	buf := make([]byte, 2048)
	for {
		n, src, err := ls.ReadFromUDP(buf)
		if err != nil {
			return // сокет закрыт при пересадке/остановке — штатно
		}
		d := make([]byte, n)
		copy(d, buf[:n])
		w.onRx()
		w.datch <- inPkt{data: d, src: src}
	}
}

// onRx — факт приёма по v6-проводу: снимает окно тишины и возвращает
// провод из отката (возврат только по ФАКТУ приёма, не по отправке).
func (w *wireV6) onRx() {
	w.lastRx.Store(time.Now().Unix())
	w.sentSince.Store(0)
	w.fails.Store(0)
	if w.ok.CompareAndSwap(false, true) {
		w.downAt.Store(0)
		log.Printf("wire6: по v6-проводу снова идут ответы — возвращаю его в строй")
	}
}

// watchdog — детект молчаливой чёрной дыры и периодическая перепроба.
func (w *wireV6) watchdog() {
	tk := time.NewTicker(3 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-w.stop:
			return
		case <-tk.C:
			w.tick(time.Now().Unix())
		}
	}
}

// tick — один шаг watchdogа (вынесен для детерминированных тестов:
// ждать реальные 12с в тесте нечестно и медленно).
func (w *wireV6) tick(now int64) {
	if w.ok.Load() {
		sent := w.sentSince.Load()
		age := now - w.lastRx.Load()
		if sent < wire6MinSentToTrip || age <= wire6SilenceSec {
			return
		}
		if w.ok.CompareAndSwap(true, false) {
			w.downAt.Store(now)
			log.Printf("wire6: отправлено %d датаграмм, ответов по v6 нет %dс — причина в строках wire6src/v6rot выше: либо нет нативного v6, либо пул не запинен мимо туннеля, либо путь режется; откат на v4-провод, перепроба через %dс", sent, age, wire6RetryDownSec)
		}
		return
	}
	if d := w.downAt.Load(); d != 0 && now-d >= wire6RetryDownSec {
		w.downAt.Store(now)
		w.sentSince.Store(0)
		w.lastRx.Store(now) // свежее окно на пробу
		if w.ok.CompareAndSwap(false, true) {
			log.Printf("wire6: перепроба v6-провода (окно %dс)", wire6SilenceSec)
		}
	}
}

func (w *wireV6) rebindLoop() {
	if w.rotSec == 0 {
		return
	}
	tk := time.NewTicker(time.Duration(w.rotSec) * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-w.stop:
			return
		case <-tk.C:
			if err := w.rebind(); err != nil {
				log.Printf("wire6: пересадка порта: %v", err)
			}
		}
	}
}

// nextDst — случайный адрес пула ноды для очередной датаграммы.
func (w *wireV6) nextDst() (*net.UDPAddr, error) {
	a, err := randV6(w.pool)
	if err != nil {
		return nil, err
	}
	return &net.UDPAddr{IP: a, Port: w.port}, nil
}

// nextSrc — сокет со случайным исходным адресом (либо единственный).
func (w *wireV6) nextSrc() *net.UDPConn {
	if w.src != nil {
		if s := w.src.pick(); s != nil {
			return s
		}
	}
	s, _ := w.cur.Load().(*net.UDPConn)
	return s
}

// send — одна датаграмма: случайный источник -> случайное назначение.
func (w *wireV6) send(b []byte) error {
	if !w.ok.Load() {
		return errWire6Down
	}
	dst, err := w.nextDst()
	if err != nil {
		return err
	}
	sock := w.nextSrc()
	if sock == nil {
		return errWire6Down
	}
	if _, err := sock.WriteToUDP(b, dst); err != nil {
		if n := w.fails.Add(1); n >= wireFailsToFallback && w.ok.CompareAndSwap(true, false) {
			w.downAt.Store(time.Now().Unix())
			log.Printf("wire6: %d отправок подряд с ошибкой (%v) — нативного v6 нет или он мёртв; откат на v4-провод, перепроба через %dс", n, err, wire6RetryDownSec)
		}
		return err
	}
	w.fails.Store(0)
	w.sentSince.Add(1)
	return nil
}

// probe — принудительная проба по v6 в откате (keepalive): шлём мимо ok,
// в строй провод вернёт только реально пришедший ответ (onRx).
func (w *wireV6) probe(b []byte) bool {
	dst, err := w.nextDst()
	if err != nil {
		return false
	}
	sock := w.nextSrc()
	if sock == nil {
		return false
	}
	_, err = sock.WriteToUDP(b, dst)
	return err == nil
}

// wire6Status — строка состояния для лога стадий.
func (w *wireV6) status() string {
	if w == nil {
		return "-"
	}
	state := "v4-откат"
	if w.ok.Load() {
		state = "v6"
	}
	if w.src != nil {
		return state + "/источников:" + itoa(w.src.count())
	}
	return state
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 && i > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func (w *wireV6) close() {
	close(w.stop)
	if s, ok := w.cur.Load().(*net.UDPConn); ok {
		s.Close()
	}
}
