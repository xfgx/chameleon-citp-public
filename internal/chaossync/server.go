package chaossync

// server.go — fail-closed мультиплексор ноды.
//
// Нода молчит на ВСЁ, пока источник не доказал знание мастер-ключа самим
// фактом синхронизма (residual его потока упал до уровня квантования —
// без ключа это недостижимо). Никаких ответов на пробы цензора: снаружи
// порт неотличим от фильтрованного. Это прямое продолжение философии
// blackhole/strike-list из Priority 0 проекта.
//
// Анти-усиление: s2c-поток идёт только адресам с недавней активностью и
// только пока доказательство живо. Динамика s2c — единый осциллятор ноды.

import (
	"sort"
	"sync"
	"time"
)

const (
	maxPeers       = 256              // верхняя граница наблюдателей
	proofTimeout   = 30 * time.Second // не доказал за 30 с → вытеснение
	idleTimeout    = 60 * time.Second // нет датаграмм → вытеснение
	txActiveWindow = 15 * time.Second // слать s2c только активным
)

type peerState struct {
	rx       *Endpoint // наблюдатель c2s-направления (TX-часть не используется)
	lastSeen time.Time
	proven   bool
	provenAt time.Time
}

// ServerMux — fail-closed мультиплексор: карта наблюдателей по адресам +
// общий s2c-осциллятор.
type ServerMux struct {
	cfg   Config
	tx    *Endpoint // s2c-осциллятор (RX-часть не используется)
	peers map[string]*peerState
	mu    sync.Mutex // единая защита карты peers: read-цикл, тикер и http-метрики — 3 горутины
}

// NewServerMux — новый мультиплексор с общим мастер-ключом.
func NewServerMux(cfg Config) *ServerMux {
	cfg = cfg.withDefaults()
	return &ServerMux{
		cfg:   cfg,
		tx:    NewEndpoint(cfg, "s2c"),
		peers: make(map[string]*peerState),
	}
}

// Handle — входящая датаграмма от адреса from. Возвращает true, если
// источник доказал знание ключа (синхронизм) и ему разрешён s2c-поток.
func (m *ServerMux) Handle(dat []byte, from string, now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	ps, ok := m.peers[from]
	if !ok {
		if len(m.peers) >= maxPeers {
			if !m.evictOne(now) {
				return false // молчание: таблица полна доказанными
			}
		}
		ps = &peerState{rx: NewEndpoint(m.cfg, "s2c")}
		m.peers[from] = ps
	}
	ps.lastSeen = now
	ps.rx.HandleDatagram(dat, now)
	if !ps.proven && ps.rx.Locked() {
		ps.proven = true
		ps.provenAt = now
	}
	return ps.proven
}

// Enqueue — приём c2s-датаграммы в джиттер-буфер наблюдателя (Э5): БЕЗ
// немедленной обработки. Обработка — в TickPeers по локальным часам ноды, что
// отделяет часы сэмплов от сетевого джиттера. Потеря = underrun очереди.
func (m *ServerMux) Enqueue(dat []byte, from string, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ps, ok := m.peers[from]
	if !ok {
		if len(m.peers) >= maxPeers {
			if !m.evictOne(now) {
				return
			}
		}
		ps = &peerState{rx: NewEndpoint(m.cfg, "s2c")}
		m.peers[from] = ps
	}
	ps.lastSeen = now
	ps.rx.EnqueueDatagram(dat, now)
}

// TickPeers — обработать джиттер-очереди всех наблюдателей по локальным часам.
// Возвращает адреса свежеДОКАЗАННЫХ пиров (для логов). Вызывать с периодом
// DatagramInterval().
func (m *ServerMux) TickPeers(now time.Time) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var newly []string
	for a, ps := range m.peers {
		ps.rx.TickRx(now)
		if !ps.proven && ps.rx.Locked() {
			ps.proven = true
			ps.provenAt = now
			newly = append(newly, a)
		}
	}
	if len(newly) > 0 {
		sort.Strings(newly)
	}
	return newly
}

// Tick — очередная s2c-датаграмма и отсортированный список адресов,
// которым её слать (доказанные и активные). Вызывать с периодом
// DatagramInterval().
func (m *ServerMux) Tick(now time.Time) ([]string, []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	dat := m.tx.NextDatagram(now)
	var addrs []string
	for a, ps := range m.peers {
		if ps.proven && now.Sub(ps.lastSeen) < txActiveWindow {
			addrs = append(addrs, a)
		}
	}
	sort.Strings(addrs)
	return addrs, dat
}

// Cleanup — вытеснение недоказавших и молчащих. Вызывать периодически.
func (m *ServerMux) Cleanup(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for a, ps := range m.peers {
		idle := now.Sub(ps.lastSeen)
		if (!ps.proven && idle > proofTimeout) || idle > idleTimeout {
			delete(m.peers, a)
		}
	}
}

// evictOne — вытеснение самого старого НЕдоказанного наблюдателя.
func (m *ServerMux) evictOne(now time.Time) bool {
	var oldest string
	var oldestT time.Time
	for a, ps := range m.peers {
		if ps.proven {
			continue
		}
		if oldest == "" || ps.lastSeen.Before(oldestT) {
			oldest, oldestT = a, ps.lastSeen
		}
	}
	if oldest == "" {
		return false
	}
	delete(m.peers, oldest)
	return true
}

// PeerCount — (всего, доказанных).
func (m *ServerMux) PeerCount() (int, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	proven := 0
	for _, ps := range m.peers {
		if ps.proven {
			proven++
		}
	}
	return len(m.peers), proven
}

// PeerSnapshot — срез состояния наблюдателя адреса (nil, если нет такого).
func (m *ServerMux) PeerSnapshot(from string) *Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	ps, ok := m.peers[from]
	if !ok {
		return nil
	}
	s := ps.rx.Snapshot()
	return &s
}

// PeerFrames — входящие проверенные кадры от адреса.
func (m *ServerMux) PeerFrames(from string) []ParsedFrame {
	m.mu.Lock()
	defer m.mu.Unlock()
	ps, ok := m.peers[from]
	if !ok {
		return nil
	}
	return ps.rx.Frames()
}

// PushFrame — кадр в s2c-поток (общий осциллятор ноды).
func (m *ServerMux) PushFrame(payload []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tx.PushFrame(payload)
}
