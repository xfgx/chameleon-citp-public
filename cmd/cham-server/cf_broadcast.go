package main

// cf_broadcast.go — рассыльщик θ-распределения (слой 8) и карты дорогих зон
// (слой 6) по bulletin-борду Control Fabric.
//
// Каждый клиент получает свои каналы борда: идентификаторы выводятся из
// публичного ключа (ControlSessionIDFor), сообщения шифруются общим
// SessionSecret и привязываются к эпохе (PublishControlSingle — один
// AEAD-кадр на сообщение). Публикация: сразу по handshake клиента и далее на
// каждую смену эпохи для всех недавно виденных клиентов.
//
// Карта дорогих зон собирается из кандидатов, отсэмплированных из текущего θ
// (64 синтетических генома эпохи): leverage зон отражает реальную вложенность
// текущего распределения в защищённые классы.

import (
	"fmt"
	"log"
	"sync"
	"time"

	"chameleon/internal/chameleon"
)

// sessionRegistry — недавно виденные клиенты (получатели рассылки).
// Bounded, TTL 6 часов.
type sessionRegistry struct {
	mu sync.Mutex
	m  map[[32]byte]time.Time
}

func newSessionRegistry() *sessionRegistry {
	return &sessionRegistry{m: make(map[[32]byte]time.Time)}
}

func (r *sessionRegistry) Add(pub []byte) {
	if len(pub) != 32 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.m) >= 256 {
		cutoff := time.Now().Add(-6 * time.Hour)
		for k, t := range r.m {
			if t.Before(cutoff) {
				delete(r.m, k)
			}
		}
		if len(r.m) >= 256 {
			for k := range r.m { // аварийное вытеснение одной записи
				delete(r.m, k)
				break
			}
		}
	}
	var k [32]byte
	copy(k[:], pub)
	r.m[k] = time.Now()
}

func (r *sessionRegistry) List() [][32]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := time.Now().Add(-6 * time.Hour)
	out := make([][32]byte, 0, len(r.m))
	for k, t := range r.m {
		if t.After(cutoff) {
			out = append(out, k)
		}
	}
	return out
}

// ThetaBroadcaster — периодическая рассылка θ и карты дорогих зон.
type ThetaBroadcaster struct {
	cf    *chameleon.ControlFabric
	reg   *sessionRegistry
	theta chameleon.Theta
	as    string

	stopCh    chan struct{}
	once      sync.Once
	lastEpoch uint64
}

func NewThetaBroadcaster(cf *chameleon.ControlFabric, reg *sessionRegistry, th chameleon.Theta, as string) *ThetaBroadcaster {
	if as == "" {
		as = "unknown"
	}
	return &ThetaBroadcaster{cf: cf, reg: reg, theta: th, as: as, stopCh: make(chan struct{})}
}

// Start запускает эпохальный цикл рассылки (проверка раз в минуту).
func (b *ThetaBroadcaster) Start() {
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-b.stopCh:
				return
			case now := <-t.C:
				epoch := chameleon.EpochAt(now, chameleon.DefaultScheduleEpochLen)
				if epoch != b.lastEpoch {
					b.lastEpoch = epoch
					b.broadcastAll(now)
				}
			}
		}
	}()
}

func (b *ThetaBroadcaster) Stop() { b.once.Do(func() { close(b.stopCh) }) }

// mapForEpoch собирает slim-карту дорогих зон из кандидатов текущей эпохи.
func (b *ThetaBroadcaster) mapForEpoch(now time.Time) []byte {
	epoch := chameleon.EpochAt(now, chameleon.DefaultScheduleEpochLen)
	cands := make([]chameleon.FlowProfile, 0, 64)
	for i := 0; i < 64; i++ {
		g := chameleon.DeriveGenome(b.theta, b.cf.SessionSecret(), epoch,
			[]byte(fmt.Sprintf("synthetic-%d", i)))
		cands = append(cands, chameleon.FlowProfileFromFlavor(g.Fingerprint, g.Flavor))
	}
	cm := chameleon.NewCollateralMap(b.as, cands).Slim()
	data, err := chameleon.EncodeCollateralMapSlim(cm)
	if err != nil {
		return nil
	}
	return data
}

// PublishTo публикует θ и карту дорогих зон одному клиенту (по его pubkey).
func (b *ThetaBroadcaster) PublishTo(pub []byte, now time.Time) {
	tb, err := chameleon.EncodeTheta(b.theta)
	if err != nil {
		return
	}
	mb := b.mapForEpoch(now)
	sidT := chameleon.ControlSessionIDFor(pub, "theta")
	if err := b.cf.PublishControlSingle(sidT, tb); err != nil {
		log.Printf("cf-broadcast: theta: %v", err)
	}
	if mb != nil {
		sidC := chameleon.ControlSessionIDFor(pub, "collateral")
		if err := b.cf.PublishControlSingle(sidC, mb); err != nil {
			log.Printf("cf-broadcast: collateral: %v", err)
		}
	}
}

// broadcastAll рассылает всем недавно виденным клиентам (смена эпохи).
func (b *ThetaBroadcaster) broadcastAll(now time.Time) {
	sids := b.reg.List()
	for _, pub := range sids {
		b.PublishTo(pub[:], now)
	}
	if len(sids) > 0 {
		log.Printf("cf-broadcast: θ и карта дорогих зон разосланы %d клиентам (эпоха %d)",
			len(sids), chameleon.EpochAt(now, chameleon.DefaultScheduleEpochLen))
	}
}

// Пакетные синглтоны: заполняются в main при включённой рассылке.
var (
	sessReg *sessionRegistry
	thetaBC *ThetaBroadcaster
)
