#!/usr/bin/env python3
# Раунд 4: суррогат в автопилоте (слой 1) + двусторонние канарейки (слой 3).
import sys

EDITS = []
APPENDS = {}

AP = "/files/VPN/cmd/chamd/autopilot.go"
M = "/files/VPN/cmd/chamd/manager.go"
MN = "/files/VPN/cmd/chamd/main.go"

# --- manager.go: хук onSessionUp ---

EDITS.append((M, """	onSessionDrop func()            // хук «сеанс умер» (зовётся асинхронно)""", """	onSessionDrop func()            // хук «сеанс умер» (зовётся асинхронно)
	onSessionUp   func()            // хук «сеанс поднят» (зовётся асинхронно; слой 3: выжившие канарейки)"""))

EDITS.append((M, """// SetOnSessionDrop регистрирует колбэк на смерть сеанса (автопилот).
func (m *Manager) SetOnSessionDrop(fn func()) { m.onSessionDrop = fn }""", """// SetOnSessionDrop регистрирует колбэк на смерть сеанса (автопилот).
func (m *Manager) SetOnSessionDrop(fn func()) { m.onSessionDrop = fn }

// SetOnSessionUp регистрирует колбэк на успешный подъём сеанса (автопилот).
func (m *Manager) SetOnSessionUp(fn func()) { m.onSessionUp = fn }"""))

EDITS.append((M, """	m.logf("подключено: %s. Сеанс мультиплексирует все потоки.", srv.Name)
	if m.onConnect != nil {
		m.onConnect()
	}
	return nil""", """	m.logf("подключено: %s. Сеанс мультиплексирует все потоки.", srv.Name)
	if m.onConnect != nil {
		m.onConnect()
	}
	if m.onSessionUp != nil {
		go m.onSessionUp() // слой 3: канарейка дожила до сеанса
	}
	return nil"""))

EDITS.append((M, """		mx = chameleon.NewMuxClient(conn)
		if m.cbr > 0 {
			f := m.flavor()
			mx.Conn().StartShaper(f.Base, f.Jitter, f.MinPad, f.MaxPad, "c2s-cbr")
		}
		m.mux = mx
	}""", """		mx = chameleon.NewMuxClient(conn)
		if m.cbr > 0 {
			f := m.flavor()
			mx.Conn().StartShaper(f.Base, f.Jitter, f.MinPad, f.MaxPad, "c2s-cbr")
		}
		m.mux = mx
		if m.onSessionUp != nil {
			go m.onSessionUp() // слой 3: канарейка дожила до сеанса (реконнект)
		}
	}"""))

# --- autopilot.go: поле surrogate, вызов переобучения, новые функции ---

EDITS.append((AP, """	theta       *chameleon.Theta
	lastGenome  *chameleon.Genome
	canaries    chameleon.CanaryTracker
}""", """	theta       *chameleon.Theta
	lastGenome  *chameleon.Genome
	canaries    chameleon.CanaryTracker
	surrogate   *chameleon.Surrogate // слой 1: обучаемая копия границы DPI
}"""))

EDITS.append((AP, """	a.recordNetprofile(prof, plan) // F1: накопление модели среды""", """	a.recordNetprofile(prof, plan) // F1: накопление модели среды
	a.retrainSurrogate() // слой 1: суррогат из журнала own+exo"""))

APPENDS[AP] = """
// OnSessionUp — хук Manager «сеанс поднят». Слой 3: канареечный геном,
// доживший до сеанса, записывается как выживший — счётчик выживаемости
// канареек становится двусторонним (обрывы пишет OnSessionDrop).
func (a *Autopilot) OnSessionUp() {
	a.mu.Lock()
	g := a.lastGenome
	a.mu.Unlock()
	if g != nil && g.Canary {
		a.canaries.Record(true)
		a.m.logf("autopilot: канареечный геном дожил до сеанса (выживаемость %.2f на %d пробах)",
			a.canaries.Survival(), a.canaries.Samples())
	}
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
	last := obs[len(obs)-1]
	p := s.Predict(chameleon.ObsFeatures(last))
	note := fmt.Sprintf("суррогат: %d наблюдений, p(блок|последний вектор)=%.2f", len(obs), p)
	a.m.SetAutoNote(note)
	if g != nil {
		a.m.logf("autopilot: %s; текущий геном fp=%s canary=%v", note, g.Fingerprint, g.Canary)
	} else {
		a.m.logf("autopilot: %s", note)
	}
}
"""

# --- main.go: регистрация хука ---

EDITS.append((MN, """	m.SetOnSessionDrop(ap.OnSessionDrop)""", """	m.SetOnSessionDrop(ap.OnSessionDrop)
	m.SetOnSessionUp(ap.OnSessionUp) // слой 3: выжившие канарейки"""))

contents = {}
for path, old, _new in EDITS + [(p, "", "") for p in APPENDS]:
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

for path, block in APPENDS.items():
    contents[path] = contents[path].rstrip("\n") + "\n" + block

for path, text in contents.items():
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    print("PATCHED", path)
