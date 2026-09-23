package chameleon

// cf_car_ack.go — Этап B3: обратный канал клиент→нода (ack/heartbeat) поверх
// RST-инъекций цензора.
//
// Идея: клиент инициирует запросы, триггерящие RST-инъекцию ТСПУ в сторону
// измерительного endpoint'а ноды; нода пассивно наблюдает долю оборванных
// соединений и декодирует короткий ack. Бит 1 = всплеск оборванных
// соединений в окне, бит 0 = тишина.
//
// В ЛАБОРАТОРИИ RST производит сам отправитель (TCP SetLinger(0)+Close) —
// для ноды это неотличимо от RST, инъецированного on-path цензором: и там и
// там соединение умирает до передачи данных. В боевом режиме клиент вместо
// этого дёргает trigger-URL ноды, а RST в обе стороны вносит ТСПУ — код
// наблюдателя на ноде один и тот же.

import (
	"net"
	"sync"
	"time"
)

// CARAckObserver — нодская сторона обратного канала: слушает измерительный
// endpoint и считает соединения, оборванные до первого байта данных.
type CARAckObserver struct {
	addr string
	ln   net.Listener

	mu        sync.Mutex
	aborted   int
	closeOnce sync.Once
	done      chan struct{}
}

// NewCARAckObserver создаёт наблюдателя на addr (host:port).
func NewCARAckObserver(addr string) *CARAckObserver {
	return &CARAckObserver{addr: addr, done: make(chan struct{})}
}

// Serve принимает соединения и классифицирует каждое: умерло до первого
// байта (RST/EOF/таймаут) -> aborted++. Блокирует до Close.
func (o *CARAckObserver) Serve() error {
	ln, err := net.Listen("tcp", o.addr)
	if err != nil {
		return err
	}
	o.mu.Lock()
	o.ln = ln
	o.mu.Unlock()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go o.classify(conn)
	}
}

func (o *CARAckObserver) classify(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	var b [1]byte
	if _, err := conn.Read(b[:]); err != nil {
		// RST (connection reset), чистый EOF до данных или тишина —
		// всё это «оборванное» соединение для целей канала.
		o.mu.Lock()
		o.aborted++
		o.mu.Unlock()
	}
}

// ReadBit наблюдает одно окно: счётчик обрывов обнуляется, ждём window,
// бит 1 если обрывов >= threshold.
func (o *CARAckObserver) ReadBit(window time.Duration, threshold int) uint8 {
	o.mu.Lock()
	o.aborted = 0
	o.mu.Unlock()
	t := time.NewTimer(window)
	select {
	case <-o.done:
		t.Stop()
		return 0
	case <-t.C:
	}
	o.mu.Lock()
	n := o.aborted
	o.mu.Unlock()
	if n >= threshold {
		return 1
	}
	return 0
}

// ReadBits читает n бит подряд (n окон).
func (o *CARAckObserver) ReadBits(n int, window time.Duration, threshold int) []uint8 {
	out := make([]uint8, n)
	for i := 0; i < n; i++ {
		out[i] = o.ReadBit(window, threshold)
	}
	return out
}

// Addr — фактический адрес прослушивания (после Serve).
func (o *CARAckObserver) Addr() string {
	o.mu.Lock()
	ln := o.ln
	o.mu.Unlock()
	if ln == nil {
		return ""
	}
	return ln.Addr().String()
}

// Close останавливает наблюдателя.
func (o *CARAckObserver) Close() error {
	o.closeOnce.Do(func() { close(o.done) })
	o.mu.Lock()
	ln := o.ln
	o.mu.Unlock()
	if ln == nil {
		return nil
	}
	return ln.Close()
}

// CARAckSender — клиентская сторона: кодирует биты всплесками оборванных
// соединений. В лаборатории обрыв делает сам клиент (linger-0 RST); в бою
// вместо этого запрашиваются trigger-URL, а рвёт соединения ТСПУ.
type CARAckSender struct {
	Burst int           // сколько RST-соединений в всплеске на бит 1
	Gap   time.Duration // пауза между соединениями внутри всплеска
}

// NewCARAckSender — дефолтный отправитель: всплеск из 3 RST с шагом 40 мс.
func NewCARAckSender() *CARAckSender {
	return &CARAckSender{Burst: 3, Gap: 40 * time.Millisecond}
}

// SendBits передаёт биты по окнам длительностью window: бит 1 — всплеск RST
// в начале окна, бит 0 — тишина. Блокирует на всё время передачи.
func (s *CARAckSender) SendBits(addr string, bits []uint8, window time.Duration) {
	burst := s.Burst
	if burst < 1 {
		burst = 3
	}
	gap := s.Gap
	if gap <= 0 {
		gap = 40 * time.Millisecond
	}
	for _, bit := range bits {
		start := time.Now()
		if bit == 1 {
			for i := 0; i < burst; i++ {
				s.rstOnce(addr)
				if i+1 < burst {
					time.Sleep(gap)
				}
			}
		}
		if rest := window - time.Since(start); rest > 0 {
			time.Sleep(rest)
		}
	}
}

// rstOnce открывает TCP-соединение и рвёт его с RST до передачи данных —
// точный аналог соединения, убитого ТСПУ после SYN.
func (s *CARAckSender) rstOnce(addr string) {
	conn, err := net.DialTimeout("tcp", addr, 800*time.Millisecond)
	if err != nil {
		return
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	_ = conn.Close()
}
