package chameleon

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Shaper — формирователь ритма трафика против поведенческого анализа ТСПУ.
//
// Две угрозы, которые закрывает:
//  1. «Молчаливый туннель»: VPN долго молчит, потом внезапный двунаправленный
//     обмен — так не ведёт себя обычный HTTPS-сёрфинг.
//  2. Ритм пакетов: стабильные интервалы keep-alive выдают туннель.
//
// Решение: фоновая отправка кадров с плавающим интервалом (база ± джиттер).
// Если за интервал реальных данных не было — уходит кадр-паддинг случайного
// размера. Внешне — равномерный «шумовой» битрейт без пауз.
type Shaper struct {
	conn   *Conn
	d      *DRBG
	base   time.Duration
	jitter time.Duration
	minPad int
	maxPad int

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
}

// StartShaper запускает фоновый шейпинг. label отдельный на каждой стороне —
// ритм не требует синхронизации с приёмником, размеры кадров он не читает.
func (c *Conn) StartShaper(base, jitter time.Duration, minPad, maxPad int, label string) *Shaper {
	base = max(5*time.Millisecond, min(base, 2*time.Second))
	jitter = max(0, min(jitter, 2*time.Second))
	minPad = max(0, min(minPad, maxPaddingPayload))
	maxPad = max(minPad, min(maxPad, maxPaddingPayload))
	ctx, cancel := context.WithCancel(context.Background())
	s := &Shaper{
		conn:   c,
		d:      NewDRBG(c.profSeed(label), "shaper-"+label),
		base:   base,
		jitter: jitter,
		minPad: minPad,
		maxPad: maxPad,
		ctx:    ctx,
		cancel: cancel,
		done:   make(chan struct{}),
	}
	go s.loop()
	return s
}

// profSeed — доступ к seed сессии для производного DRBG шейпера.
func (c *Conn) profSeed(_ string) []byte { return c.seed }

func (s *Shaper) loop() {
	defer close(s.done)
	burstCounter := 0
	for {
		// Динамическая мульти-модальная рандомизация интервалов
		ivl := s.base
		if s.jitter > 0 {
			ivl += time.Duration(s.d.Intn(int(s.jitter)))
		}

		// 1. Имитация случайных пауз человека / микро-задержек (micro-sleeps)
		burstCounter++
		if burstCounter >= 10+s.d.Intn(20) {
			burstCounter = 0
			// Внезапная пауза смены фокуса (от 100 до 600 мс), разрушающая периодичность CBR
			extraPause := time.Duration(100+s.d.Intn(500)) * time.Millisecond
			ivl += extraPause
		}

		select {
		case <-s.ctx.Done():
			return
		case <-time.After(ivl):
		}

		// Если реальные данные отправлялись недавно — пропускаем
		sinceLast := time.Since(time.Unix(0, s.conn.lastUsefulSend.Load()))
		if sinceLast < s.base {
			continue
		}

		// 2. Полная рандомизация размера паддинга (гауссов/длиннохвостый шум)
		n := s.minPad
		if s.maxPad > s.minPad {
			// Рандомизация с нерегулярным шагом
			n += s.d.Intn(s.maxPad - s.minPad)
		}

		// 3. Пакетные всплески (micro-bursts): 1..3 коротких кадра вместо строго одного
		burstCount := 1
		if s.d.Intn(8) == 0 {
			burstCount = 2 + s.d.Intn(2)
		}

		for b := 0; b < burstCount; b++ {
			padSize := n
			if b > 0 && s.maxPad > s.minPad {
				padSize = s.minPad + s.d.Intn(s.maxPad-s.minPad)
			}
			if _, err := s.conn.TryWritePadding(padSize); err != nil {
				return
			}
		}
	}
}

// Stop останавливает шейпер и ждёт завершения горутины. Идемпотентен.
func (s *Shaper) Stop() {
	s.once.Do(func() {
		s.cancel()
	})
	<-s.done
}

// PackMorph — интеллектуальная мимикрия трафика.
//
// Анализирует текущий сетевой профиль (размеры пакетов, интервалы, протоколы)
// и динамически подстраивает параметры шейпинга так, чтобы трафик CITP
// классифицировался ML-моделью DPI как легитимный сервис (Zoom, YouTube, Steam).
//
// PackMorph использует данные о реальном трафике пользователя для построения
// статистически невыдающегося профиля. Если обнаруживается, что текущий
// профиль «светится», PackMorph автоматически меняет параметры.
type PackMorph struct {
	conn       *Conn
	d          *DRBG
	profile    *TrafficProfileSnapshot
	targetMode TrafficMode
	mu         sync.Mutex
	ctx        context.Context
	cancel     context.CancelFunc
	done       chan struct{}
	once       sync.Once
}

// TrafficMode — целевой режим мимикрии.
type TrafficMode int

const (
	ModeAuto        TrafficMode = iota // автоматический выбор на основе анализа
	ModeZoom                           // имитация видеозвонка Zoom
	ModeYouTube                        // имитация просмотра YouTube
	ModeSteam                          // имитация загрузки Steam
	ModeWebBrowsing                    // имитация веб-сёрфинга
	ModeGaming                         // имитация игрового трафика
)

// TrafficProfileSnapshot — снимок профиля трафика для анализа.
type TrafficProfileSnapshot struct {
	AvgSize     float64
	SizeStdDev  float64
	AvgInterval float64
	IatStdDev   float64
	ByteRate    float64
	PacketRate  float64
	SizeHist    map[int]int
	ProtoMix    map[string]int
}

// ModeParams — параметры шейпинга для конкретного режима.
type ModeParams struct {
	BaseInterval   time.Duration
	Jitter         time.Duration
	MinPad         int
	MaxPad         int
	BurstProb      int // вероятность micro-burst (0-100)
	MicroSleepProb int // вероятность micro-sleep (0-100)
}

// ModeProfiles — параметры для каждого режима мимикрии.
var ModeProfiles = map[TrafficMode]ModeParams{
	ModeZoom: {
		BaseInterval:   20 * time.Millisecond,
		Jitter:         10 * time.Millisecond,
		MinPad:         800,
		MaxPad:         1400,
		BurstProb:      30,
		MicroSleepProb: 5,
	},
	ModeYouTube: {
		BaseInterval:   15 * time.Millisecond,
		Jitter:         8 * time.Millisecond,
		MinPad:         1000,
		MaxPad:         1460,
		BurstProb:      40,
		MicroSleepProb: 2,
	},
	ModeSteam: {
		BaseInterval:   15 * time.Millisecond,
		Jitter:         8 * time.Millisecond,
		MinPad:         1200,
		MaxPad:         1460,
		BurstProb:      50,
		MicroSleepProb: 1,
	},
	ModeWebBrowsing: {
		BaseInterval:   80 * time.Millisecond,
		Jitter:         60 * time.Millisecond,
		MinPad:         150,
		MaxPad:         800,
		BurstProb:      10,
		MicroSleepProb: 20,
	},
	ModeGaming: {
		BaseInterval:   30 * time.Millisecond,
		Jitter:         15 * time.Millisecond,
		MinPad:         60,
		MaxPad:         200,
		BurstProb:      20,
		MicroSleepProb: 10,
	},
}

// StartPackMorph запускает адаптивный шейпинг с анализом трафика.
func (c *Conn) StartPackMorph(mode TrafficMode) *PackMorph {
	if mode < ModeAuto || mode > ModeGaming { mode = ModeAuto }
	ctx, cancel := context.WithCancel(context.Background())
	pm := &PackMorph{
		conn:       c,
		d:          NewDRBG(c.profSeed("packmorph"), "packmorph"),
		targetMode: mode,
		ctx:        ctx,
		cancel:     cancel,
		done:       make(chan struct{}),
	}
	go pm.loop()
	return pm
}

// UpdateProfile обновляет профиль трафика для анализа PackMorph.
func (pm *PackMorph) UpdateProfile(snapshot *TrafficProfileSnapshot) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.profile = snapshot
}

// DetectMode анализирует профиль трафика и определяет, какой режим мимикрии
// лучше всего подходит. Используется для автоматического переключения.
func (pm *PackMorph) DetectMode() TrafficMode {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.detectModeLocked()
}

// detectModeLocked requires pm.mu to be held by the caller.
func (pm *PackMorph) detectModeLocked() TrafficMode {
	if pm.profile == nil {
		return ModeWebBrowsing
	}

	p := pm.profile

	// Анализ пакетной скорости и размера
	if p.ByteRate > 5000000 && p.AvgSize > 800 {
		// Высокая скорость + большие пакеты = видео/стриминг
		if p.PacketRate > 50 {
			return ModeYouTube
		}
		return ModeZoom
	}

	if p.ByteRate > 1000000 && p.AvgSize > 500 {
		// Средняя скорость + средние пакеты = Steam/игры
		return ModeSteam
	}

	if p.AvgSize < 200 && p.PacketRate > 10 {
		// Маленькие пакеты, высокая частота = игровой трафик
		return ModeGaming
	}

	// По умолчанию — веб-сёрфинг
	return ModeWebBrowsing
}

// IsProfileSuspicious анализирует профиль и определяет, «светится» ли трафик.
// Возвращает true, если текущий профиль отличается от целевого режима.
func (pm *PackMorph) IsProfileSuspicious() bool {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.profile == nil {
		return false
	}

	mode := pm.targetMode
	if mode == ModeAuto {
		mode = pm.detectModeLocked()
	}

	params := ModeProfiles[mode]
	p := pm.profile

	// Проверка отклонения размера пакетов
	if p.AvgSize > 0 {
		expectedMin := float64(params.MinPad)
		expectedMax := float64(params.MaxPad)
		if p.AvgSize < expectedMin*0.5 || p.AvgSize > expectedMax*2 {
			return true
		}
	}

	// Проверка интервала
	if p.AvgInterval > 0 {
		expectedBase := float64(params.BaseInterval.Milliseconds())
		if p.AvgInterval < expectedBase*0.1 || p.AvgInterval > expectedBase*10 {
			return true
		}
	}

	return false
}

// AdaptIfSuspicious проверяет, «светится» ли трафик, и при необходимости
// автоматически меняет параметры шейпинга.
func (pm *PackMorph) AdaptIfSuspicious() {
	if !pm.IsProfileSuspicious() {
		return
	}
	pm.mu.Lock()
	mode := pm.targetMode
	if mode == ModeAuto {
		mode = pm.detectModeLocked()
		pm.targetMode = mode
	}
	pm.mu.Unlock()
	fmt.Printf("PackMorph: профиль подозрителен, переключение на режим %d\n", mode)
}

func (pm *PackMorph) loop() {
	defer close(pm.done)
	burstCounter := 0
	checkInterval := 30 * time.Second
	lastCheck := time.Now()

	for {
		select {
		case <-pm.ctx.Done():
			return
		default:
		}

		// Периодически проверяем профиль и адаптируемся
		if time.Since(lastCheck) >= checkInterval {
			pm.AdaptIfSuspicious()
			lastCheck = time.Now()
		}

		pm.mu.Lock()
		mode := pm.targetMode
		if mode == ModeAuto {
			mode = pm.detectModeLocked()
		}
		params := ModeProfiles[mode]
		pm.mu.Unlock()

		// Динамическая рандомизация интервала
		ivl := params.BaseInterval
		if params.Jitter > 0 {
			ivl += time.Duration(pm.d.Intn(int(params.Jitter)))
		}

		// Имитация micro-sleeps
		burstCounter++
		if burstCounter >= 10+pm.d.Intn(20) {
			burstCounter = 0
			if pm.d.Intn(100) < params.MicroSleepProb {
				extraPause := time.Duration(100+pm.d.Intn(500)) * time.Millisecond
				ivl += extraPause
			}
		}

		select {
		case <-pm.ctx.Done():
			return
		case <-time.After(ivl):
		}

		// Если реальные данные отправлялись недавно — пропускаем
		sinceLast := time.Since(time.Unix(0, pm.conn.lastUsefulSend.Load()))
		if sinceLast < params.BaseInterval {
			continue
		}

		// Рандомизация размера паддинга
		n := params.MinPad
		if params.MaxPad > params.MinPad {
			n += pm.d.Intn(params.MaxPad - params.MinPad)
		}

		// Micro-bursts
		burstCount := 1
		if pm.d.Intn(100) < params.BurstProb {
			burstCount = 2 + pm.d.Intn(2)
		}

		for b := 0; b < burstCount; b++ {
			padSize := n
			if b > 0 && params.MaxPad > params.MinPad {
				padSize = params.MinPad + pm.d.Intn(params.MaxPad-params.MinPad)
			}
			if _, err := pm.conn.TryWritePadding(padSize); err != nil {
				return
			}
		}
	}
}

// Stop останавливает PackMorph и ждёт завершения горутины. Идемпотентен.
func (pm *PackMorph) Stop() {
	pm.once.Do(func() {
		pm.cancel()
	})
	<-pm.done
}
