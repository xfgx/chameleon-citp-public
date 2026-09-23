#!/usr/bin/env python3
# Точечные правки обвязки автопилота (слои 7/8) + manager.go + main.go.
# Каждый якорь обязан встречаться ровно один раз — иначе фатал, файлы не тронуты.
import sys

EDITS = []

A = "/files/VPN/cmd/chamd/autopilot.go"
M = "/files/VPN/cmd/chamd/manager.go"
MN = "/files/VPN/cmd/chamd/main.go"

# --- autopilot.go ---

EDITS.append((A, """	mu       sync.Mutex
	lastProf chameleon.CensorProfile
	lastPlan chameleon.BypassPlan
	hasRun   bool
	drops    []time.Time
	lastRun  time.Time
}""", """	mu       sync.Mutex
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
}"""))

EDITS.append((A, """type netprofileRecord struct {
	TS            string   `json:"ts"`""", """type netprofileRecord struct {
	TS            string   `json:"ts"`
	Src           string   `json:"src,omitempty"` // own|exo (слой 7)"""))

EDITS.append((A, """	rec := netprofileRecord{
		TS:            time.Now().UTC().Format(time.RFC3339),""", """	rec := netprofileRecord{
		TS:            time.Now().UTC().Format(time.RFC3339),
		Src:           chameleon.SrcOwn,"""))

EDITS.append((A, """	go a.loop()
	go a.scheduleLoop()
}""", """	go a.loop()
	go a.scheduleLoop()
	go a.exoLoop()
}"""))

EDITS.append((A, """	a.drops = kept
	n := len(a.drops)
	a.mu.Unlock()""", """	a.drops = kept
	n := len(a.drops)
	g := a.lastGenome
	a.mu.Unlock()
	// Слой 3: обрыв канареечного генома идёт в выживаемость канареек.
	if g != nil && g.Canary {
		a.canaries.Record(false)
		if a.canaries.ShouldBumpEpoch(0.6, 5) {
			a.m.logf("autopilot: КАНАРЕЙКИ: выживаемость ниже порога (%d проб) — похоже, цензор обновил правила; форс-репрофиль",
				a.canaries.Samples())
			go a.profileAndApply("канареечный триггер")
		}
	}"""))

EDITS.append((A, """	var hint chameleon.ControlFabricNodeHint
	if err := json.Unmarshal(msg, &hint); err != nil {
		a.m.logf("autopilot: борд: некорректный hint (%v)", err)
		return
	}""", """	// Слои 6–8: борд может нести не только node-hint, но и θ-распределение /
	// карту дорогих зон / grad-статистики — классифицируем по полю kind.
	if kind := chameleon.ControlMessageKind(msg); kind != "node-hint" {
		a.handleBoardMessage(kind, msg)
		return
	}
	var hint chameleon.ControlFabricNodeHint
	if err := json.Unmarshal(msg, &hint); err != nil {
		a.m.logf("autopilot: борд: некорректный hint (%v)", err)
		return
	}"""))

EDITS.append((A, """		case "tcp_reset_or_sni_interference":
			f := a.m.RotateFlavor()
			a.m.SetAutoNote("смена маски ритма → " + f)
			a.m.logf("autopilot: RST/SNI-интерференция → смена flavor на %s и реконнект", f)
			a.m.ForceReconnect("RST/SNI-интерференция")""", """		case "tcp_reset_or_sni_interference":
			desc := a.rotateStrategyFor(a.m.ActiveServerEntry())
			a.m.SetAutoNote("смена маски ритма → " + desc)
			a.m.logf("autopilot: RST/SNI-интерференция → %s; реконнект", desc)
			a.m.ForceReconnect("RST/SNI-интерференция")"""))

NEW_FUNCS = """
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
		g := chameleon.DeriveGenome(*th, []byte("chameleon-control-fabric:"+entry.CFSeed), epoch, a.m.ClientPubBytes())
		a.m.SetGenomeFlavor(g.Flavor)
		a.mu.Lock()
		a.lastGenome = &g
		a.mu.Unlock()
		desc := fmt.Sprintf("θ-геном эпохи %d (base=%s, jitter=%s, pad=%d..%d)",
			g.Epoch, g.Flavor.Base, g.Flavor.Jitter, g.Flavor.MinPad, g.Flavor.MaxPad)
		if g.Canary {
			desc += " [канарейка]"
		}
		return desc
	}
	return "flavor " + a.m.RotateFlavor()
}
"""

# --- manager.go ---

EDITS.append((M, """	pinMap        map[string]string // DoH-пин: IP:port → исходный domain:port
	autoNote      atomic.Value      // string: последнее действие автопилота (для панели)""", """	pinMap        map[string]string // DoH-пин: IP:port → исходный domain:port
	autoNote      atomic.Value      // string: последнее действие автопилота (для панели)
	genomeFlavor  *chameleon.Flavor // слой 8: одноразовый геном из θ (nil = обычный flavorName)"""))

EDITS.append((M, """	m.flavorName = next
	return next
}""", """	m.flavorName = next
	m.genomeFlavor = nil // ручная/legacy ротация отменяет θ-геном
	return next
}

// SetGenomeFlavor применяет одноразовый геном, выведенный из θ-распределения
// (слой 8): следующий сеанс стартует с этими параметрами ритма.
func (m *Manager) SetGenomeFlavor(f chameleon.Flavor) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.genomeFlavor = &f
}"""))

EDITS.append((M, """// flavor возвращает flavor текущего сеанса; "auto" — случайный RU-сервис.
func (m *Manager) flavor() chameleon.Flavor {
	m.mu.RLock()
	name := m.flavorName
	m.mu.RUnlock()""", """// flavor возвращает flavor текущего сеанса; "auto" — случайный RU-сервис.
// Если автопилот применил θ-геном (слой 8), он имеет приоритет над списком.
func (m *Manager) flavor() chameleon.Flavor {
	m.mu.RLock()
	name := m.flavorName
	g := m.genomeFlavor
	m.mu.RUnlock()
	if g != nil {
		return *g
	}"""))

# --- main.go ---

EDITS.append((MN, """	autopilotOn := flag.Bool("autopilot", true, "автопилот: профилирование сети и авто-обход (DoH-резолв нод, ротация flavor/decoy, чтение борда при обрывах)")""", """	autopilotOn := flag.Bool("autopilot", true, "автопилот: профилирование сети и авто-обход (DoH-резолв нод, ротация flavor/decoy, чтение борда при обрывах)")
	exoOn := flag.Bool("exo", true, "слой 7: экзогенная сенсорика — пулл публичных измерений OONI (RU) в data/netprofile.jsonl")"""))

EDITS.append((MN, """	ap.SetDataDir(*dataDir) // F1: netprofile.jsonl пишется в каталог данных""", """	ap.SetDataDir(*dataDir) // F1: netprofile.jsonl пишется в каталог данных
	ap.SetExo(*exoOn, "")   // слой 7: экзогенная сенсорика (OONI)"""))

# --- применение ---

contents = {}
for path, old, _new in EDITS:
    if path not in contents:
        with open(path, encoding="utf-8") as f:
            contents[path] = f.read()

for path, old, new in EDITS:
    src = contents[path]
    n = src.count(old)
    if n != 1:
        print("FATAL: якорь встречается %d раз (нужно 1) в %s:\n%s" % (n, path, old[:120]))
        sys.exit(1)
    contents[path] = src.replace(old, new)

with open(A, encoding="utf-8") as f:
    contents[A] = f.read()
for path, old, new in EDITS:
    if path == A and old in contents[A]:
        pass
# повторно применяем правки A к уже изменённому тексту (они сделаны выше по цепочке)
src = contents[A]
for path, old, new in EDITS:
    if path != A:
        continue
    if old in src:
        src = src.replace(old, new)
contents[A] = src + NEW_FUNCS

for path, text in contents.items():
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    print("PATCHED", path)
