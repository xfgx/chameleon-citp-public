#!/usr/bin/env python3
# Рассылка θ/карты дорогих зон: правки main.go (флаги+запуск+hook) и
# autopilot.go (опрос broadcast-каналов), append-блоки в библиотеке.
import sys

EDITS = []
APPENDS = {}

MS = "/files/VPN/cmd/cham-server/main.go"
AP = "/files/VPN/cmd/chamd/autopilot.go"
CF = "/files/VPN/internal/chameleon/control_fabric.go"
IH = "/files/VPN/internal/chameleon/cf_integration_hints.go"
CL = "/files/VPN/internal/chameleon/cf_collateral.go"

# --- main.go ---

EDITS.append((MS, """	ttlsSecret := flag.String("ttls-secret", "", "TTLS-фронт: общий с клиентами секрет (PSK); пустой = детерминированный из ключа ноды (печатается в журнал)")
	flag.Parse()""", """	ttlsSecret := flag.String("ttls-secret", "", "TTLS-фронт: общий с клиентами секрет (PSK); пустой = детерминированный из ключа ноды (печатается в журнал)")
	cfThetaBroadcast := flag.Bool("cf-theta-broadcast", true, "слои 6/8: рассылка θ-распределения и карты дорогих зон по борду (по handshake и на смену эпохи)")
	cfThetaFile := flag.String("cf-theta-file", "", "JSON-файл θ-распределения оператора (пустой = DefaultTheta)")
	cfCollateralAS := flag.String("cf-collateral-as", "", "ASN зоны для карты дорогих зон (пустой = unknown)")
	flag.Parse()"""))

EDITS.append((MS, """	if cf != nil {
		log.Printf("Control Fabric enabled: channels=%v", cf.Names())
	}""", """	if cf != nil {
		log.Printf("Control Fabric enabled: channels=%v", cf.Names())
	}

	// Слои 6/8: рассыльщик θ-распределения и карты дорогих зон по борду.
	if cf != nil && *cfThetaBroadcast {
		th := chameleon.DefaultTheta()
		if *cfThetaFile != "" {
			if b, err := os.ReadFile(*cfThetaFile); err != nil {
				log.Printf("cf-theta-file %s: %v — откат на DefaultTheta", *cfThetaFile, err)
			} else if t2, err := chameleon.DecodeTheta(b); err != nil {
				log.Printf("cf-theta-file %s: %v — откат на DefaultTheta", *cfThetaFile, err)
			} else {
				th = t2
			}
		}
		sessReg = newSessionRegistry()
		thetaBC = NewThetaBroadcaster(cf, sessReg, th, *cfCollateralAS)
		thetaBC.Start()
		defer thetaBC.Stop()
		log.Printf("cf-broadcast: рассылка θ (canary=%.2f%%, leak=%.0f бит/эпоху) и карты дорогих зон (as=%s) включена",
			th.CanaryFrac*100, th.LeakBits, *cfCollateralAS)
	}"""))

EDITS.append((MS, """		if err := cf.PublishControl(context.Background(), sessionID, chameleon.ControlBootstrapHint()); err != nil {
			log.Printf("control-fabric publish failed for %s: %v", ip, err)
		}
	}""", """		if err := cf.PublishControl(context.Background(), sessionID, chameleon.ControlBootstrapHint()); err != nil {
			log.Printf("control-fabric publish failed for %s: %v", ip, err)
		}
		// Слои 6/8: клиенту сразу уезжают θ и карта дорогих зон (свои каналы борда).
		if thetaBC != nil {
			sessReg.Add(clientPub)
			thetaBC.PublishTo(clientPub, time.Now())
		}
	}"""))

# --- autopilot.go: опрос broadcast-каналов при каждом pollBoard ---

EDITS.append((AP, """	sid := chameleon.ControlSessionID(pub)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)""", """	sid := chameleon.ControlSessionID(pub)
	go a.pollBoardChannels(entry, pub) // слои 6/8: θ и карта дорогих зон — независимо от hint
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)"""))

APPENDS[AP] = """
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
"""

# --- control_fabric.go: однокадровая публикация ---

APPENDS[CF] = """
// PublishControlSingle публикует управляющее сообщение ОДНИМ AEAD-кадром на
// произвольный идентификатор канала борда (слои 6/8: рассылка θ и карты
// дорогих зон). В отличие от PublishControl, сообщение не дробится на
// 180-байтные чанки: каждый кадр канала — самостоятельное сообщение, поэтому
// периодическая рассылка эпох в один канал не ломает сборку — клиент
// дешифрует кадры независимо и берёт последний валидный (PollChannelMessages).
func (cf *ControlFabric) PublishControlSingle(channelID string, msg []byte) error {
	if len(msg) > MaxControlMessage {
		return errors.New("control-fabric: control message too large")
	}
	cf.mu.Lock()
	cdn := cf.cdn
	cf.mu.Unlock()
	if cdn == nil {
		return errors.New("control-fabric: no bulletin channel")
	}
	enc, err := AEADEncrypt(cf.SessionSecret(), cf.bindMessage(msg, time.Now()))
	if err != nil {
		return err
	}
	cdn.Publish(channelID, enc)
	return nil
}
"""

# --- cf_integration_hints.go: производные идентификаторы каналов ---

APPENDS[IH] = """
// ControlSessionIDFor — идентификатор broadcast-канала борда (слои 6/8):
// производный от публичного ключа клиента sid, не пересекающийся с
// hint-каналом (ControlSessionID) за счёт доменного разделителя. Тот же
// 22-символьный base64url-формат — проходит валидацию sid на воркере.
func ControlSessionIDFor(clientPub []byte, channel string) string {
	h := sha256.New()
	h.Write([]byte("cf-channel:"))
	h.Write([]byte(channel))
	h.Write([]byte{0})
	h.Write(clientPub)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:16])
}
"""

# --- cf_collateral.go: проводной slim-формат карты ---

APPENDS[CL] = """
// --- проводной формат карты для борда (слой 6) ---

// CollateralZoneSlim — зона без профиля: референсные профили детерминированно
// восстанавливаются клиентом из DefaultProtectedClasses (те же Flavors),
// по сети не передаются — карта помещается в один кадр борда.
type CollateralZoneSlim struct {
	Class    string  `json:"class"`
	Cost     float64 `json:"cost"`
	Leverage float64 `json:"leverage"`
}

// CollateralMapSlim — проводной формат CollateralMap для рассылки бордом.
type CollateralMapSlim struct {
	Kind       string               `json:"kind"` // CollateralKind
	V          int                  `json:"v"`
	AS         string               `json:"as"`
	MeasuredAt time.Time            `json:"measured_at"`
	Zones      []CollateralZoneSlim `json:"zones"`
}

// Slim отбрасывает профили зон для проводного формата.
func (m CollateralMap) Slim() CollateralMapSlim {
	s := CollateralMapSlim{Kind: m.Kind, V: m.V, AS: m.AS, MeasuredAt: m.MeasuredAt}
	for _, z := range m.Zones {
		s.Zones = append(s.Zones, CollateralZoneSlim{Class: z.Class, Cost: z.Cost, Leverage: z.Leverage})
	}
	return s
}

// EncodeCollateralMapSlim кодирует проводной формат карты для борда.
func EncodeCollateralMapSlim(s CollateralMapSlim) ([]byte, error) { return json.Marshal(s) }
"""

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
