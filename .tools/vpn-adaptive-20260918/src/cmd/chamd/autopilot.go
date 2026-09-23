package main

// autopilot.go — «измеряет и обходит»: автопилот chamd.
//
// Связка: DPI-профайлер (internal/chameleon/cf_profiler.go) ->
// AdaptiveCarrierSelector (cf_bypass.go) -> исполнение ЛОКАЛЬНЫХ действий
// прямо в клиенте:
//
//	dns_likely_hijack            -> резолв адресов нод через DoH (обход перехвата DNS)
//	http_block_page              -> ротация decoy-целей cover-трафика
//	tcp_reset/sni-интерференция  -> ротация CBR-flavor + форсированный реконнект
//
// Плюс heartbeat: серия обрывов сеанса -> ре-профилирование + чтение
// bulletin-борда Control Fabric (next-entry) перед реконнектом.
//
// Этап F (docs/ROADMAP-CENSOR-TRANSPORT.md):
//   - F1: каждый профиль сети дописывается в data/netprofile.jsonl —
//     накопление наблюдений для будущей модели цензора (пока расписание
//     синхронизировано на встроенной канонической модели v1);
//   - F2: помимо событийного опроса (серия обрывов), борд опрашивается в
//     точках Schedule.BoardPollAt текущей эпохи — моменты выводятся из
//     DRBG(secret‖модель‖эпоха) и не образуют фиксированного таймер-паттерна;
//   - F2/F3: чтение борда и CAR идёт с проверкой привязки к эпохе и
//     смещением окна кодовой книги (см. cf_schedule_runtime.go).
//
// Автопилот — добавочный слой над Manager: существующие настройки и
// поведение по умолчанию не меняются, все действия логируются в панель.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"chameleon/internal/chameleon"
)

const (
	autopilotInterval  = 10 * time.Minute // периодический ре-профиль
	autopilotDropWin   = 3 * time.Minute  // окно подсчёта обрывов
	autopilotDropCount = 2                // обрывов в окне -> реакция
	autopilotMinRun    = 2 * time.Minute  // минимум между профилями

	schedPollTick   = 45 * time.Second // период проверки точек расписания эпохи
	schedPollWindow = 90 * time.Second // окно срабатывания точки BoardPollAt

	netprofileMaxBytes = 1 << 20 // ротация netprofile.jsonl
	netprofileKeep     = 256     // строк после ротации
)

// Autopilot — фоновый контур «профиль -> план -> исполнение».
type Autopilot struct {
	m     *Manager
	cover *Cover

	dohEndpoint string
	bypassAdd   func(ip string) // TUN: вывести точку замера мимо туннеля (опционально)
	dataDir     string          // каталог данных (netprofile.jsonl)

	stopCh    chan struct{}
	stopOnce  sync.Once
	firstDone chan struct{}
	firstOnce sync.Once

	mu       sync.Mutex
	lastProf chameleon.CensorProfile
	lastPlan chameleon.BypassPlan
	hasRun   bool
	drops    []time.Time
	lastRun  time.Time

	// Слой 7 (экзогенная сенсорика) и слои 6/8 (сообщения борда):
	exoOn       bool   // -exo: пулл OONI в netprofile.jsonl
	exoEndpoint string // переопределение endpoint OONI (тесты)
	theta       *chameleon.Theta
	lastGenome  *chameleon.Genome
	canaries    chameleon.CanaryTracker
	surrogate   *chameleon.Surrogate // слой 1: обучаемая копия границы DPI
	genomeHistory []chameleon.Genome // последние применённые геномы (для novelty, ≤64)
	leak          *chameleon.LeakBudget
	leakEpoch     uint64
	survival *chameleon.StrategySurvivalModel
	strategyHistoryMu sync.Mutex
	strategyRound uint64
}

func NewAutopilot(m *Manager, cover *Cover) *Autopilot {
	defaultTheta := chameleon.DefaultTheta()
	a := &Autopilot{
		m:           m,
		cover:       cover,
		dohEndpoint: "https://1.1.1.1/dns-query",
		stopCh:      make(chan struct{}),
		firstDone:   make(chan struct{}),
		theta: &defaultTheta,
		survival: chameleon.NewStrategySurvivalModel(),
	}
	if m != nil {
		m.muxMu.Lock()
		m.strategyObserver = a.captureStrategy
		m.muxMu.Unlock()
	}
	return a
}

// SetBypassAdder подключает обходной маршрут для проб в TUN-режиме — тогда
// периодический профиль меряет сеть провайдера, а не собственный туннель.
func (a *Autopilot) SetBypassAdder(fn func(ip string)) { a.bypassAdd = fn }

// SetDataDir задаёт каталог данных клиента (туда пишется netprofile.jsonl, F1).
func (a *Autopilot) SetDataDir(dir string) {
	a.mu.Lock()
	a.dataDir = dir
	a.mu.Unlock()
	a.loadStrategyHistory(dir)
}

// FirstRunDone закрывается после первого профиля; main ждёт его (с капом по
// времени) перед автоподключением, чтобы замер шёл по сети провайдера.
func (a *Autopilot) FirstRunDone() <-chan struct{} { return a.firstDone }

// Start запускает первый профиль немедленно (асинхронно) и периодические контуры.
func (a *Autopilot) Start() {
	go func() {
		a.profileAndApply("старт")
		a.firstOnce.Do(func() { close(a.firstDone) })
	}()
	go a.loop()
	go a.scheduleLoop()
	go a.exoLoop()
}

func (a *Autopilot) Stop() { a.stopOnce.Do(func() { close(a.stopCh) }) }

func (a *Autopilot) loop() {
	t := time.NewTimer(autopilotInterval)
	defer t.Stop()
	for {
		select {
		case <-a.stopCh:
			return
		case <-t.C:
			a.profileAndApply("периодический контроль")
			t.Reset(autopilotInterval)
		}
	}
}

// scheduleLoop — этап F2: плановый опрос борда в моменты, выведенные из
// DRBG(secret‖modelHash‖эпоха). У каждой эпохи свои 2-3 точки — у
// наблюдателя нет стабильного паттерна опроса. Событийный опрос (серия
// обрывов) сохраняется поверх.
func (a *Autopilot) scheduleLoop() {
	fired := make(map[string]uint64) // "epoch/slot" -> epoch (для уборки)
	t := time.NewTicker(schedPollTick)
	defer t.Stop()
	for {
		select {
		case <-a.stopCh:
			return
		case now := <-t.C:
			entry, ok := a.m.ActiveServerEntry()
			if !ok || entry.CFSeed == "" || entry.CFBoardURL == "" {
				continue
			}
			cf := chameleon.NewControlFabric([]byte("chameleon-control-fabric:"+entry.CFSeed), nil, nil, nil, nil).
				WithSchedule(nil, 0)
			sched := cf.CurrentSchedule(now)
			if sched == nil {
				continue
			}
			epochLenSec := int64(cf.ScheduleEpochLen() / time.Second)
			epochStart := time.Unix(int64(sched.Epoch)*epochLenSec, 0)
			for i, off := range sched.BoardPollAt {
				key := fmt.Sprintf("%d/%d", sched.Epoch, i)
				if _, dup := fired[key]; dup {
					continue
				}
				at := epochStart.Add(off)
				if !now.Before(at) && now.Sub(at) < schedPollWindow {
					fired[key] = sched.Epoch
					a.m.logf("autopilot: расписание эпохи %d — плановый опрос борда (слот %d)", sched.Epoch, i)
					go a.pollBoard()
				}
			}
			// уборка: забываем слоты эпох старше текущей-1
			for k, e := range fired {
				if e+1 < sched.Epoch {
					delete(fired, k)
				}
			}
		}
	}
}

// OnSessionDrop — хук Manager: сеанс умер. Серия обрывов в окне -> реакция.
func (a *Autopilot) OnSessionDrop() {
	a.mu.Lock()
	now := time.Now()
	a.drops = append(a.drops, now)
	cut := now.Add(-autopilotDropWin)
	kept := a.drops[:0]
	for _, d := range a.drops {
		if d.After(cut) {
			kept = append(kept, d)
		}
	}
	a.drops = kept
	n := len(a.drops)
	a.mu.Unlock()
	// Per-session monitors own outcome attribution; the current genome may differ.

	if n >= autopilotDropCount {
		go a.profileAndApply("серия обрывов сеанса")
		go a.pollBoard()
	}
}

// profileAndApply прогоняет профайлер и исполняет локальные действия плана.
func (a *Autopilot) profileAndApply(reason string) {
	a.mu.Lock()
	if time.Since(a.lastRun) < autopilotMinRun {
		a.mu.Unlock()
		return
	}
	a.lastRun = time.Now()
	a.mu.Unlock()

	// В TUN-режиме выводим точку замера (1.1.1.1) мимо туннеля — иначе
	// профилируем собственный VPN, а не сеть провайдера.
	if a.bypassAdd != nil {
		a.bypassAdd("1.1.1.1")
	}

	cfg := chameleon.ProfilerConfig{
		ProbeDomains:    []string{"google.com", "cloudflare.com", "github.com"},
		ProbeHTTPURLs:   []string{"https://www.google.com/", "https://github.com/"},
		BlockSignatures: []string{"<title>blocked</title>", "доступ ограничен"},
		DoHEndpoint:     a.dohEndpoint,
		Timeout:         8 * time.Second,
	}
	ctx := context.Background()
	prof := chameleon.NewDPIProfiler(cfg).Run(ctx)
	plan := chameleon.NewAdaptiveCarrierSelector(chameleon.DefaultCarrierProfiles()).Select(prof)

	a.mu.Lock()
	a.lastProf, a.lastPlan, a.hasRun = prof, plan, true
	a.mu.Unlock()

	a.m.logf("autopilot (%s): dpi=%v dns_hijack=%v rst=%v sni=%v blockpage=%v (resolver plain=%s doh=%s)",
		reason, prof.HasDPI, prof.DNSLikelyHijack, prof.TCPResetInjection, prof.TLSInterference, prof.HTTPBlockPage,
		prof.ResolverPlain, prof.ResolverDoH)
	a.recordNetprofile(prof, plan) // F1: накопление модели среды
	a.retrainSurrogate()           // слой 1: суррогат из журнала own+exo
	a.applyPlan(prof, plan)
}

// netprofileRecord — одна строка наблюдения за сетью (этап F1). Формат
// канонический (JSON по строке): из этих записей позже собирается обновлённая
// модель цензора для DeriveSchedule; сама запись секретов не содержит.
type netprofileRecord struct {
	TS            string   `json:"ts"`
	Src           string   `json:"src,omitempty"` // own|exo (слой 7)
	HasDPI        bool     `json:"dpi"`
	DNSHijack     bool     `json:"dns_hijack"`
	TCPReset      bool     `json:"tcp_reset"`
	TLSInterf     bool     `json:"tls_interference"`
	HTTPBlockPage bool     `json:"http_block_page"`
	ResolverPlain string   `json:"resolver_plain,omitempty"`
	ResolverDoH   string   `json:"resolver_doh,omitempty"`
	BlockSigs     []string `json:"block_signatures,omitempty"`
	Actions       int      `json:"actions"`
}

// recordNetprofile дописывает наблюдение в <dataDir>/netprofile.jsonl (0600)
// с ротацией по размеру. Ошибки записи не влияют на работу — только лог.
func (a *Autopilot) recordNetprofile(prof chameleon.CensorProfile, plan chameleon.BypassPlan) {
	a.mu.Lock()
	dir := a.dataDir
	a.mu.Unlock()
	if dir == "" {
		return
	}
	path := filepath.Join(dir, "netprofile.jsonl")
	if st, err := os.Stat(path); err == nil && st.Size() > netprofileMaxBytes {
		rotateNetprofile(path)
	}
	rec := netprofileRecord{
		TS:            time.Now().UTC().Format(time.RFC3339),
		Src:           chameleon.SrcOwn,
		HasDPI:        prof.HasDPI,
		DNSHijack:     prof.DNSLikelyHijack,
		TCPReset:      prof.TCPResetInjection,
		TLSInterf:     prof.TLSInterference,
		HTTPBlockPage: prof.HTTPBlockPage,
		ResolverPlain: prof.ResolverPlain,
		ResolverDoH:   prof.ResolverDoH,
		BlockSigs:     prof.BlockSignatures,
		Actions:       len(plan.Actions),
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		a.m.logf("autopilot: netprofile: %v", err)
		return
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		a.m.logf("autopilot: netprofile: %v", err)
	}
}

// rotateNetprofile оставляет последние netprofileKeep строк журнала.
func rotateNetprofile(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := strings0Split(string(b))
	if len(lines) > netprofileKeep {
		lines = lines[len(lines)-netprofileKeep:]
	}
	out := ""
	for _, l := range lines {
		if l != "" {
			out += l + "\n"
		}
	}
	_ = os.WriteFile(path, []byte(out), 0o600)
}

// strings0Split — локальная обёртка, чтобы не тянуть strings ради одного места.
func strings0Split(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// applyPlan исполняет локальные действия BypassPlan. Действия идемпотентны:
// повторный профиль с тем же вердиктом не дёргает клиента повторно.
func (a *Autopilot) applyPlan(prof chameleon.CensorProfile, plan chameleon.BypassPlan) {
	for _, act := range plan.Actions {
		switch act.Trigger {
		case "dns_likely_hijack":
			if a.m.DoHMode() {
				continue
			}
			a.m.SetDoHMode(true)
			a.m.SetAutoNote("DNS→DoH: провайдер перехватывает plain-DNS")
			a.m.logf("autopilot: перехват DNS у провайдера (plain=%s ≠ doh=%s) → адреса нод резолвим через DoH",
				prof.ResolverPlain, prof.ResolverDoH)
			a.m.ForceReconnect("переход на DoH-резолв")
		case "http_block_page":
			a.cover.RotateDecoys()
			a.m.SetAutoNote("ротация decoy-целей (block-page)")
			a.m.logf("autopilot: HTTP-заглушка у провайдера → ротация decoy-целей")
		case "tcp_reset_or_sni_interference":
			desc := a.rotateStrategyFor(a.m.ActiveServerEntry())
			a.m.SetAutoNote("стратегия ритма → " + desc)
			a.m.logf("autopilot: RST/SNI-интерференция → %s; реконнект", desc)
			a.m.ForceReconnect("RST/SNI-интерференция")
		case "sni_interference_severe":
			a.m.logf("autopilot: тяжёлая SNI-фильтрация — нужна refraction-инфраструктура (по roadmap, отложено)")
		}
	}
}

// pollBoard читает bulletin-борд Control Fabric при серии обрывов и в точках
// расписания эпохи: если нода опубликовала next-entry/свежий hint —
// переключаемся на новые параметры, а не на старые. Работает, только если у
// активной ноды в servers.json заполнены cf_board_url и cf_seed (тот же
// seed, что у ноды в -cf-seed). Чтение — с проверкой привязки к эпохе (F3,
// внутри PollControlMessage).
func (a *Autopilot) pollBoard() {
	entry, ok := a.m.ActiveServerEntry()
	if !ok || entry.CFSeed == "" || (entry.CFBoardURL == "" && entry.CFCarURL == "") {
		return
	}
	if entry.CFBoardURL == "" {
		a.pollCAR()
		return
	}
	pub := a.m.ClientPubBytes()
	if len(pub) == 0 {
		return
	}
	sid := chameleon.ControlSessionID(pub)
	go a.pollBoardChannels(entry, pub) // слои 6/8: θ и карта дорогих зон — независимо от hint
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	msg, err := chameleon.PollControlMessage(ctx, entry.CFBoardURL, entry.CFSeed, sid)
	if err != nil {
		// Этап B2: борд недоступен (напр. IP ноды заблокирован, а worker тоже
		// не отвечает) -> открываем CAR-чтение. Поллим вердикт-канал только при
		// такой деградации, чтобы не светить паттерн.
		a.m.logf("autopilot: борд %s: %v — fallback на CAR-канал", entry.CFBoardURL, err)
		a.pollCAR()
		return
	}
	// Слои 6–8: борд может нести не только node-hint, но и θ-распределение /
	// карту дорогих зон / grad-статистики — классифицируем по полю kind.
	if kind := chameleon.ControlMessageKind(msg); kind != "node-hint" {
		a.handleBoardMessage(kind, msg)
		return
	}
	var hint chameleon.ControlFabricNodeHint
	if err := json.Unmarshal(msg, &hint); err != nil {
		a.m.logf("autopilot: борд: некорректный hint (%v)", err)
		return
	}
	a.m.logf("autopilot: борд отвечает: node_ip=%s board=%s", hint.NodeIP, hint.CDNBaseURL)
	// Если борд указывает другой адрес входа — логируем намерение переключиться.
	// Полноценная ротация списка нод — Фаза 2 roadmap (node directory).
	if hint.NodeIP != "" {
		if host, _, err := net.SplitHostPort(entry.Addr); err == nil && host != hint.NodeIP {
			a.m.logf("autopilot: борд указывает next-entry %s (текущий %s)", hint.NodeIP, host)
		}
	}
}

// pollCAR — этап B2: чтение управляющего сообщения по CAR-каналу, когда борд
// недоступен. Кодовая книга выводится из того же cf_seed, что и на ноде
// (DRBG от SessionSecret), со смещением окна из расписания эпохи (F2); пути
// окон и смещение по сети не передаются. Читатель учитывает block-сигнатуры
// последнего профиля сети. Поллинг только при деградации (серия обрывов +
// недоступный борд).
func (a *Autopilot) pollCAR() {
	entry, ok := a.m.ActiveServerEntry()
	if !ok || entry.CFCarURL == "" || entry.CFSeed == "" {
		return
	}
	cf := chameleon.NewControlFabric([]byte("chameleon-control-fabric:"+entry.CFSeed), nil, nil, nil, nil).
		WithSchedule(nil, 0)
	reader := chameleon.NewCARReader(entry.CFCarURL)
	a.mu.Lock()
	if a.hasRun && len(a.lastProf.BlockSignatures) > 0 {
		reader.WithBlockSignatures(a.lastProf.BlockSignatures)
	}
	a.mu.Unlock()
	msg, err := cf.ReadControlCAR(reader, 2)
	if err != nil {
		a.m.logf("autopilot: CAR %s: %v", entry.CFCarURL, err)
		return
	}
	var hint chameleon.ControlFabricNodeHint
	if err := json.Unmarshal(msg, &hint); err != nil {
		a.m.logf("autopilot: CAR: некорректный hint (%v)", err)
		return
	}
	a.m.logf("autopilot: CAR-канал отвечает: node_ip=%s car=%s (борд был недоступен)", hint.NodeIP, hint.CARBaseURL)
	if hint.NodeIP != "" {
		if host, _, err := net.SplitHostPort(entry.Addr); err == nil && host != hint.NodeIP {
			a.m.logf("autopilot: CAR указывает next-entry %s (текущий %s)", hint.NodeIP, host)
		}
	}
}

// --- Слой 7: экзогенная сенсорика (OONI -> netprofile.jsonl) ---

// SetExo включает экзогенный пулл (флаг -exo) и позволяет переопределить
// endpoint OONI (пустая строка = api.ooni.io; нужно для тестов).
func (a *Autopilot) SetExo(on bool, endpoint string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.exoOn = on
	a.exoEndpoint = endpoint
}

// exoLoop — периодический пулл чужих измерений: вердикты без единой своей
// пробы. Первый заход через 2 минуты (после стартового профиля), далее раз в
// 3 часа — вежливо к публичному API и достаточно свежо для часовых эпох.
func (a *Autopilot) exoLoop() {
	t := time.NewTimer(2 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-a.stopCh:
			return
		case <-t.C:
			a.syncExogenous("плановый пулл")
			t.Reset(3 * time.Hour)
		}
	}
}

// syncExogenous тянет свежие измерения OONI по RU и дописывает их в
// netprofile.jsonl с пометкой src=exo (дедуп по UID — в AppendObservations).
// Ошибки не влияют на работу — только журнал.
func (a *Autopilot) syncExogenous(reason string) {
	a.mu.Lock()
	on, endpoint, dir := a.exoOn, a.exoEndpoint, a.dataDir
	a.mu.Unlock()
	if !on || dir == "" {
		return
	}
	client := chameleon.NewOONIClient(endpoint)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	now := time.Now().UTC()
	obs, err := client.FetchObservations(ctx, chameleon.OONIQuery{
		ProbeCC:  "RU",
		TestName: "web_connectivity",
		Since:    now.Add(-3 * time.Hour),
		Until:    now,
		Limit:    100,
	})
	if err != nil {
		a.m.logf("autopilot: exo (%s): %v", reason, err)
		return
	}
	n, err := chameleon.AppendObservations(filepath.Join(dir, "netprofile.jsonl"), obs, netprofileMaxBytes, netprofileKeep)
	if err != nil {
		a.m.logf("autopilot: exo (%s): запись: %v", reason, err)
		return
	}
	a.m.logf("autopilot: exo (%s): +%d наблюдений OONI (окно 3ч, получено %d)", reason, n, len(obs))
}

// --- Слои 6/8/1: сообщения борда новых типов ---

// handleBoardMessage разбирает управляющее сообщение борда не-hint типов:
// θ-распределение (слой 8), карта дорогих зон (слой 6), grad-статистики (слой 1).
func (a *Autopilot) handleBoardMessage(kind string, msg []byte) {
	switch kind {
	case chameleon.ThetaKind:
		th, err := chameleon.DecodeTheta(msg)
		if err != nil {
			a.m.logf("autopilot: борд: некорректная θ (%v)", err)
			return
		}
		a.mu.Lock()
		a.theta = &th
		a.mu.Unlock()
		a.m.SetAutoNote("θ-распределение от борда")
		a.m.logf("autopilot: борд прислал θ-распределение: base %d..%d мс, pad %d..%d, канарейки %.1f%%, leak-бюджет %.0f бит/эпоху",
			th.BaseMsLo, th.BaseMsHi, th.MinPadLo, th.MaxPadHi, th.CanaryFrac*100, th.LeakBits)
	case chameleon.CollateralKind:
		cm, err := chameleon.DecodeCollateralMap(msg)
		if err != nil {
			a.m.logf("autopilot: борд: некорректная карта дорогих зон (%v)", err)
			return
		}
		best, bestL := "", 0.0
		for _, z := range cm.Zones {
			if z.Leverage > bestL {
				best, bestL = z.Class, z.Leverage
			}
		}
		a.m.logf("autopilot: борд прислал карту дорогих зон %s: %d зон, лучшая %s (leverage %.2f)",
			cm.AS, len(cm.Zones), best, bestL)
	case chameleon.GradStatsKind:
		a.m.logf("autopilot: борд прислал grad-статистики суррогата (применение — следующий этап федерации)")
	default:
		a.m.logf("autopilot: борд: неизвестный тип сообщения %q — игнорирую", kind)
	}
}

// --- Слой 8: применение θ вместо простой ротации flavor ---

// rotateStrategyFor выбирает новую маску ритма при RST/SNI-интерференции.
// Если от борда есть θ и у активной ноды заполнен cf_seed — выводит
// одноразовый геном HKDF(seed‖epoch‖client_pub) (слой 8); иначе — legacy
// ротация по списку flavor'ов. Возвращает описание для журнала/панели.
func (a *Autopilot) rotateStrategyFor(entry ServerEntry, ok bool) string {
	a.mu.Lock()
	th := a.theta
	a.mu.Unlock()
	if th != nil && ok && entry.CFSeed != "" {
		epoch := chameleon.EpochAt(time.Now(), time.Hour)
		if err := chameleon.ValidateTheta(*th); err != nil { return "некорректная θ; стратегия сохранена" }
		a.mu.Lock()
		lb := a.leakBudgetFor(epoch, *th)
		if !lb.TrySpend(1) {
			a.mu.Unlock()
			return "бюджет новых стратегий исчерпан; текущая маска сохранена"
		}
		round := a.strategyRound
		a.strategyRound++
		a.mu.Unlock()
		seed := []byte("chameleon-control-fabric:" + entry.CFSeed)
		clientSalt := binary.BigEndian.AppendUint64(append([]byte(nil), a.m.ClientPubBytes()...), round)
		g, detail := a.selectGenome(*th, seed, epoch, clientSalt)
		a.m.SetGenomeFlavor(g.Flavor)
		a.mu.Lock()
		a.lastGenome = &g
		a.genomeHistory = append(a.genomeHistory, g)
		if len(a.genomeHistory) > 64 {
			a.genomeHistory = a.genomeHistory[len(a.genomeHistory)-64:]
		}
		a.mu.Unlock()
		// The budget is an exposure policy, not a measured Shannon leakage bound.
		desc := fmt.Sprintf("θ-геном эпохи %d (base=%s, jitter=%s, pad=%d..%d; %s; leak %.0f%% бюджета)",
			g.Epoch, g.Flavor.Base, g.Flavor.Jitter, g.Flavor.MinPad, g.Flavor.MaxPad,
			detail, lb.SpentFrac()*100)
		if g.Canary {
			desc += " [канарейка]"
		}
		return desc
	}
	fallbackTheta := chameleon.DefaultTheta()
	if th != nil { fallbackTheta = *th }
	if err := chameleon.ValidateTheta(fallbackTheta); err != nil { return "некорректная θ; стратегия сохранена" }
	epoch := chameleon.EpochAt(time.Now(), time.Hour)
	a.mu.Lock()
	if !a.leakBudgetFor(epoch, fallbackTheta).TrySpend(1) {
		a.mu.Unlock()
		return "бюджет новых стратегий исчерпан; текущая маска сохранена"
	}
	a.lastGenome = nil
	a.mu.Unlock()
	return "flavor " + a.m.RotateFlavor()
}

// pollBoardChannels опрашивает broadcast-каналы борда (θ-распределение и карта
// дорогих зон) независимо от hint-канала: каждый кадр канала — самостоятельное
// сообщение (PublishControlSingle), берём последний валидный.
func (a *Autopilot) pollBoardChannels(entry ServerEntry, clientPub []byte) {
	if entry.CFBoardURL == "" || entry.CFSeed == "" || len(clientPub) == 0 {
		return
	}
	for _, ch := range []struct {
		name string
		kind string
	}{
		{"theta", chameleon.ThetaKind},
		{"collateral", chameleon.CollateralKind},
	} {
		id := chameleon.ControlSessionIDFor(clientPub, ch.name)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		msgs, err := chameleon.PollChannelMessages(ctx, entry.CFBoardURL, entry.CFSeed, id)
		cancel()
		if err != nil || len(msgs) == 0 {
			continue
		}
		last := msgs[len(msgs)-1]
		if k := chameleon.ControlMessageKind(last); k == ch.kind {
			a.handleBoardMessage(k, last)
		}
	}
}

// OnSessionUp is only a handshake notification. Survival requires useful
// bidirectional traffic and the observation horizon in strategy_session.go.
func (a *Autopilot) OnSessionUp() {
	a.m.logf("autopilot: сеанс поднят; handshake не считается доказательством устойчивости")
}

// retrainSurrogate — слой 1: обучаем локальную копию решающей границы цензора
// на журнале наблюдений (own+exo, взвешенных по доверию к источнику и
// свежести). Вызывается после каждого профиля; журнал ограничен 256
// записями, 40 проходов SGD — мгновенно.
func (a *Autopilot) retrainSurrogate() {
	a.mu.Lock()
	dir := a.dataDir
	a.mu.Unlock()
	if dir == "" {
		return
	}
	obs, err := chameleon.LoadObservations(filepath.Join(dir, "netprofile.jsonl"))
	if err != nil || len(obs) == 0 {
		return
	}
	s := chameleon.NewSurrogate(5)
	now := time.Now()
	for epoch := 0; epoch < 40; epoch++ {
		s.TrainFromObservations(obs, now, 7*24*time.Hour, 0.5)
	}
	a.mu.Lock()
	a.surrogate = s
	g := a.lastGenome
	a.mu.Unlock()
	note := fmt.Sprintf("диагностика профиля: %d наблюдений; не прогноз устойчивости кандидатов", len(obs))
	a.m.SetAutoNote(note)
	if g != nil {
		a.m.logf("autopilot: %s; текущий геном fp=%s canary=%v", note, g.Fingerprint, g.Canary)
	} else {
		a.m.logf("autopilot: %s", note)
	}
}

// leakBudgetFor — leak-бюджет текущей эпохи (вызывается под a.mu).
// Бюджет считает ЖИВУЮ экспозицию: применение генома в сети сообщает цензору
// биты о нас. Офлайн-оценка кандидатов (selectGenome) утечки не создаёт.
func (a *Autopilot) leakBudgetFor(epoch uint64, th chameleon.Theta) *chameleon.LeakBudget {
	if a.leak == nil || epoch > a.leakEpoch {
		a.leak = chameleon.NewLeakBudget(epoch, th.LeakBits)
		a.leakEpoch = epoch
	}
	a.leak.Tighten(th.LeakBits)
	return a.leak
}

// selectGenome — слои 8+6+2: выбор генома эпохи из θ-распределения.
// Базовая точка — детерминированный DeriveGenome(seed‖epoch‖client). Поверх
// неё офлайн (ноль живых проб) оцениваются K-1 дополнительных кандидатов из θ
// (детерминированная соль client‖i) по fitness: novelty против истории
// применённых геномов (слой 2, популяция без единой сигнатуры) + leverage —
// вложенность в защищённые классы (слой 6, цена ошибки цензора). Приор
// выживаемости теперь берётся из результатов конкретных завершённых сеансов,
// с контекстом до испытания, забыванием и порогом поддержки. Профайлер own/exo
// не подменяет результат испытания и не является меткой успеха кандидата.
func (a *Autopilot) selectGenome(th chameleon.Theta, seed []byte, epoch uint64, pub []byte) (chameleon.Genome, string) {
	base := chameleon.DeriveGenome(th, seed, epoch, pub)
	a.mu.Lock()
	history := append([]chameleon.Genome(nil), a.genomeHistory...)
	model := a.survival
	a.mu.Unlock()
	var entry ServerEntry
	if a.m != nil { entry, _ = a.m.ActiveServerEntry() }
	context := a.strategyContext(entry.PubKey)
	now := time.Now()

	w := chameleon.FitnessWeights{Novelty: 0.4, Leverage: 0.6}
	eval := func(g chameleon.Genome) float64 {
		fp := chameleon.FlowProfileFromFlavor(g.Fingerprint, g.Flavor)
		terms := chameleon.FitnessTerms{
			Novelty:  chameleon.NoveltyScore(g, history, 3),
			Leverage: chameleon.LeverageScore(fp, chameleon.DefaultProtectedClasses()),
		}
		score := terms.Score(w)
		if model != nil { score += model.Estimate(g.Flavor, context, now).ScoreAdjustment() }
		return score
	}

	best, bestScore, bestIdx := base, eval(base), -1
	const extra = 7 // K=8 кандидатов эпохи
	for i := 0; i < extra; i++ {
		cand := chameleon.DeriveGenome(th, seed, epoch, append(append([]byte(nil), pub...), byte(i)))
		if s := eval(cand); s > bestScore {
			best, bestScore, bestIdx = cand, s, i
		}
	}
	detail := fmt.Sprintf("fitness %.2f (лучший из %d кандидатов, соль %d)", bestScore, extra+1, bestIdx)
	if model != nil {
		estimate := model.Estimate(best.Flavor, context, now)
		detail += fmt.Sprintf("; наблюдаемая устойчивость %.2f, поддержка %.1f", estimate.Mean, estimate.Support)
	}
	return best, detail
}
