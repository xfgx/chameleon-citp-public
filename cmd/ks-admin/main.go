//go:build linux

// ks-admin - административная панель KS VPN.
//
// Собирает ТОЛЬКО статистику и метаданные: счётчики пакетов/байт, адреса
// клиентов на проводе, состояние служб и сообщения об ошибках.
// Содержимое трафика не читается, не передаётся и не хранится.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const adminVersion = "ks-admin/1.2 (2026-09-05)"

var (
	fListen    = flag.String("listen", ":51843", "адрес панели")
	fConf      = flag.String("conf", "/root/build/ks-admin.conf", "файл логина и хеша пароля")
	fDataDir   = flag.String("datadir", "/var/lib/ks-admin", "каталог истории и TLS-ключей")
	fHub       = flag.String("hub", "/run/ks-hub/status.json", "status.json многопользовательского хаба")
	fUnits     = flag.String("units", "ks-vpn-hub,ks-vpn-node,ks-vpn-phone,ks-vpn-exit", "systemd-юниты для сбора")
	fIfaces    = flag.String("ifaces", "kshub0,ks0,ksphone0,ks1", "туннельные интерфейсы")
	fPorts     = flag.String("ports", "51830:Хаб (многопользовательский),51820:ПК (старый),51822:Телефон (старый),51821:Вторая нога", "порт:метка для распознавания устройств")
	fInterval  = flag.Int("interval", 5, "период опроса счётчиков, с")
	fJInterval = flag.Int("jinterval", 15, "период чтения журнала, с")
	fPersist   = flag.Int("persist", 60, "период записи истории на диск, с (0 - не писать)")
	fHist      = flag.Int("hist", 720, "точек истории в памяти")
	fMaxLog    = flag.Int("maxlog", 16, "МиБ на файл истории до ротации")
	fMaxEvents = flag.Int("maxevents", 400, "сколько событий держать в памяти")
	fTLS       = flag.Bool("tls", true, "HTTPS с самоподписанным сертификатом")
	fSetPass   = flag.Bool("setpass", false, "задать пароль (KS_ADMIN_PASS или stdin) и выйти")
	fUser      = flag.String("user", "admin", "логин администратора")
)

// ---------- модель данных ----------

type hubUser struct {
	Name      string `json:"name"`
	Slot      int    `json:"slot"`
	Inner     string `json:"inner"`
	Online    bool   `json:"online"`
	LastRxSec int64  `json:"lastRxSec"`
	Peer      string `json:"peer"`
	PktIn     uint64 `json:"pktIn"`
	PktOut    uint64 `json:"pktOut"`
	BytesIn   uint64 `json:"bytesIn"`
	BytesOut  uint64 `json:"bytesOut"`
}

type hubStatus struct {
	Version string            `json:"version"`
	Time    string            `json:"time"`
	Inner   string            `json:"inner"`
	Self    string            `json:"self"`
	Workers int               `json:"workers"`
	Isolate bool              `json:"isolate"`
	Users   []hubUser         `json:"users"`
	Totals  map[string]uint64 `json:"totals"`
}

type ifStat struct {
	Name    string  `json:"name"`
	Up      bool    `json:"up"`
	RxBytes uint64  `json:"rxBytes"`
	TxBytes uint64  `json:"txBytes"`
	RxPkts  uint64  `json:"rxPkts"`
	TxPkts  uint64  `json:"txPkts"`
	RxErrs  uint64  `json:"rxErrs"`
	TxErrs  uint64  `json:"txErrs"`
	RxDrop  uint64  `json:"rxDrop"`
	TxDrop  uint64  `json:"txDrop"`
	RxRate  float64 `json:"rxRate"`
	TxRate  float64 `json:"txRate"`
}

type svcStat struct {
	Unit      string            `json:"unit"`
	Active    bool              `json:"active"`
	Nums      map[string]uint64 `json:"nums"`
	LastRxSec int64             `json:"lastRxSec"`
	Wire      string            `json:"wire"`
	At        time.Time         `json:"at"`
}

type connRow struct {
	Service string `json:"service"`
	Port    int    `json:"port"`
	Src     string `json:"src"`
	Sport   int    `json:"sport"`
	Dst     string `json:"dst"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

type event struct {
	Level  string    `json:"level"`
	Source string    `json:"source"`
	Msg    string    `json:"msg"`
	Count  int       `json:"count"`
	First  time.Time `json:"first"`
	Last   time.Time `json:"last"`
	key    string
}

type snapshot struct {
	At     time.Time  `json:"at"`
	Hub    *hubStatus `json:"hub,omitempty"`
	HubErr string     `json:"hubErr,omitempty"`
	Ifaces []ifStat   `json:"ifaces"`
	Svcs   []svcStat  `json:"svcs"`
	Conns  []connRow  `json:"conns"`
}

type histPoint struct {
	T    int64              `json:"t"`
	Rate map[string]float64 `json:"rate"`
}

// ---------- глобальное состояние ----------

var (
	snap      atomic.Pointer[snapshot]
	histMu    sync.Mutex
	hist      []histPoint
	evMu      sync.Mutex
	events    []*event
	evIndex   map[string]*event
	svcMu     sync.Mutex
	svcState  map[string]*svcStat
	curMu     sync.Mutex
	cursors   map[string]string
	portLabel map[int]string
	unitList  []string
	ifaceList []string
	startedAt = time.Now()
	statsFile string
	eventFile string
	devFile   string
	devMu     sync.Mutex
	devReg    map[devIdent]*devRec
	flowReg   map[flowKey]*flowVal
	lastSaved time.Time
)

func main() {
	flag.Parse()
	log.SetFlags(0)
	log.SetPrefix("[ks-admin] ")

	if *fSetPass {
		if err := setPassword(*fConf, *fUser); err != nil {
			log.Fatalf("пароль: %v", err)
		}
		log.Printf("пароль администратора %q обновлён в %s", *fUser, *fConf)
		return
	}

	unitList = splitList(*fUnits)
	ifaceList = splitList(*fIfaces)
	portLabel = parsePorts(*fPorts)
	evIndex = make(map[string]*event)
	svcState = make(map[string]*svcStat)
	cursors = make(map[string]string)

	if err := os.MkdirAll(*fDataDir, 0o750); err != nil {
		log.Fatalf("каталог %s: %v", *fDataDir, err)
	}
	statsFile = filepath.Join(*fDataDir, "stats.jsonl")
	eventFile = filepath.Join(*fDataDir, "events.jsonl")
	devFile = filepath.Join(*fDataDir, "devices.jsonl")
	devReg = map[devIdent]*devRec{}
	flowReg = map[flowKey]*flowVal{}

	c, generated, err := ensureConf(*fConf, *fUser)
	if err != nil {
		log.Fatalf("конфиг %s: %v", *fConf, err)
	}
	conf = c
	if generated != "" {
		log.Printf("СОЗДАН администратор %q, пароль: %s", conf.User, generated)
		log.Printf("смена пароля: KS_ADMIN_PASS='новый' /root/build/ks-admin -setpass")
	}
	sessions = newSessStore()
	lim = newLimiter()

	enableConntrackAcct()
	journalPoll(true)
	collectOnce()

	go loop(time.Duration(*fInterval)*time.Second, func() { collectOnce() })
	go loop(time.Duration(*fJInterval)*time.Second, func() { journalPoll(false) })
	go loop(10*time.Minute, func() { sessions.gc() })

	log.Printf("%s: панель на %s (tls=%v), юниты %v, интерфейсы %v", adminVersion, *fListen, *fTLS, unitList, ifaceList)
	if err := serve(); err != nil {
		log.Fatalf("HTTP: %v", err)
	}
}

func loop(d time.Duration, f func()) {
	if d <= 0 {
		return
	}
	tk := time.NewTicker(d)
	defer tk.Stop()
	for range tk.C {
		f()
	}
}

func splitList(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parsePorts(s string) map[int]string {
	m := map[int]string{}
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		k, v, ok := strings.Cut(p, ":")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(k))
		if err != nil || n <= 0 || n > 65535 {
			continue
		}
		m[n] = strings.TrimSpace(v)
	}
	return m
}

// ---------- сбор снапшота ----------

func collectOnce() {
	prev := snap.Load()
	s := &snapshot{At: time.Now()}
	if h, err := readHubStatus(*fHub); err == nil {
		s.Hub = h
	} else {
		s.HubErr = err.Error()
	}
	s.Ifaces = readIfaces(ifaceList)
	s.Conns = readConntrack(portLabel, 500)
	s.Svcs = svcSnapshot()
	trackDevices(s.Conns, s.At)

	rates := map[string]float64{}
	if prev != nil {
		dt := s.At.Sub(prev.At).Seconds()
		if dt > 0.2 {
			pm := map[string]ifStat{}
			for _, x := range prev.Ifaces {
				pm[x.Name] = x
			}
			for i := range s.Ifaces {
				p, ok := pm[s.Ifaces[i].Name]
				if !ok {
					continue
				}
				s.Ifaces[i].RxRate = rateOf(s.Ifaces[i].RxBytes, p.RxBytes, dt)
				s.Ifaces[i].TxRate = rateOf(s.Ifaces[i].TxBytes, p.TxBytes, dt)
				rates[s.Ifaces[i].Name] = s.Ifaces[i].RxRate + s.Ifaces[i].TxRate
			}
		}
		if prev.Hub != nil && s.Hub != nil {
			for _, k := range []string{"dropped", "spoof", "isolated", "noRoute", "noPeer", "qfull", "sendErr", "v6drop"} {
				d := int64(s.Hub.Totals[k]) - int64(prev.Hub.Totals[k])
				if d <= 0 {
					continue
				}
				lvl := "WARN"
				if k == "spoof" || k == "sendErr" {
					lvl = "ERROR"
				}
				addEvent(lvl, "ks-hub", fmt.Sprintf("счётчик %s: +%d (всего %d)", k, d, s.Hub.Totals[k]))
			}
		}
	}
	for _, f := range s.Ifaces {
		if f.RxErrs+f.TxErrs+f.RxDrop+f.TxDrop == 0 {
			continue
		}
		if prev == nil {
			continue
		}
		for _, p := range prev.Ifaces {
			if p.Name != f.Name {
				continue
			}
			if de := (f.RxErrs + f.TxErrs) - (p.RxErrs + p.TxErrs); de > 0 && de < 1<<40 {
				addEvent("ERROR", f.Name, fmt.Sprintf("ошибки интерфейса: +%d", de))
			}
			if dd := (f.RxDrop + f.TxDrop) - (p.RxDrop + p.TxDrop); dd > 0 && dd < 1<<40 {
				addEvent("WARN", f.Name, fmt.Sprintf("потери интерфейса: +%d", dd))
			}
		}
	}

	snap.Store(s)
	histAdd(histPoint{T: s.At.Unix(), Rate: rates})
	persistSample(s)
}

func rateOf(cur, prev uint64, dt float64) float64 {
	if cur < prev || dt <= 0 {
		return 0
	}
	return float64(cur-prev) / dt
}

func histAdd(p histPoint) {
	histMu.Lock()
	defer histMu.Unlock()
	hist = append(hist, p)
	if n := *fHist; n > 0 && len(hist) > n {
		hist = hist[len(hist)-n:]
	}
}

func histSnapshot() []histPoint {
	histMu.Lock()
	defer histMu.Unlock()
	out := make([]histPoint, len(hist))
	copy(out, hist)
	return out
}

// ---------- реестр устройств ----------

// Записи conntrack живут десятки секунд, поэтому панель ведёт свой
// реестр: какой адрес когда появился, сколько пробросил и когда был активен.
type devIdent struct {
	Svc string
	Src string
}

type devRec struct {
	Svc   string
	Src   string
	Port  int
	First time.Time
	Last  time.Time
	Ports map[int]bool
	Pkts  uint64
	Bytes uint64
}

type flowKey struct {
	Svc   string
	Src   string
	Sport int
	Dport int
}

type flowVal struct {
	Pkts  uint64
	Bytes uint64
	Last  time.Time
}

type devView struct {
	Svc    string `json:"svc"`
	Src    string `json:"src"`
	Port   int    `json:"port"`
	Ports  int    `json:"ports"`
	First  int64  `json:"first"`
	Last   int64  `json:"last"`
	Pkts   uint64 `json:"pkts"`
	Bytes  uint64 `json:"bytes"`
	Active bool   `json:"active"`
}

const flowIdleSec = 90

func trackDevices(conns []connRow, now time.Time) {
	devMu.Lock()
	defer devMu.Unlock()
	for _, c := range conns {
		if c.Src == "" {
			continue
		}
		id := devIdent{Svc: c.Service, Src: c.Src}
		d, ok := devReg[id]
		if !ok {
			d = &devRec{Svc: c.Service, Src: c.Src, Port: c.Port, First: now, Ports: map[int]bool{}}
			devReg[id] = d
			addEvent("INFO", "ks-admin", fmt.Sprintf("новое устройство %s на службе %s", c.Src, c.Service))
		}
		d.Last = now
		if len(d.Ports) < 4096 {
			d.Ports[c.Sport] = true
		}
		fk := flowKey{Svc: c.Service, Src: c.Src, Sport: c.Sport, Dport: c.Port}
		f, ok := flowReg[fk]
		if !ok {
			f = &flowVal{}
			flowReg[fk] = f
		}
		if c.Packets > f.Pkts {
			f.Pkts = c.Packets
		}
		if c.Bytes > f.Bytes {
			f.Bytes = c.Bytes
		}
		f.Last = now
	}
	for k, f := range flowReg {
		if now.Sub(f.Last).Seconds() < flowIdleSec {
			continue
		}
		if d, ok := devReg[devIdent{Svc: k.Svc, Src: k.Src}]; ok {
			d.Pkts += f.Pkts
			d.Bytes += f.Bytes
		}
		delete(flowReg, k)
	}
	if len(devReg) > 512 {
		type kv struct {
			id devIdent
			at time.Time
		}
		all := make([]kv, 0, len(devReg))
		for id, d := range devReg {
			all = append(all, kv{id, d.Last})
		}
		sort.Slice(all, func(i, j int) bool { return all[i].at.Before(all[j].at) })
		for i := 0; i < len(all)-512; i++ {
			delete(devReg, all[i].id)
		}
	}
}

func devSnapshot(now time.Time) []devView {
	devMu.Lock()
	defer devMu.Unlock()
	type acc struct {
		p uint64
		b uint64
	}
	active := map[devIdent]acc{}
	for k, f := range flowReg {
		id := devIdent{Svc: k.Svc, Src: k.Src}
		a := active[id]
		a.p += f.Pkts
		a.b += f.Bytes
		active[id] = a
	}
	out := make([]devView, 0, len(devReg))
	for id, d := range devReg {
		a := active[id]
		out = append(out, devView{
			Svc: d.Svc, Src: d.Src, Port: d.Port, Ports: len(d.Ports),
			First: d.First.Unix(), Last: d.Last.Unix(),
			Pkts: d.Pkts + a.p, Bytes: d.Bytes + a.b,
			Active: now.Sub(d.Last).Seconds() < flowIdleSec,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Active != out[j].Active {
			return out[i].Active
		}
		if out[i].Last != out[j].Last {
			return out[i].Last > out[j].Last
		}
		return out[i].Bytes > out[j].Bytes
	})
	return out
}

// ---------- события ----------

func addEvent(level, source, msg string) { addEventAt(level, source, msg, time.Now()) }

func addEventAt(level, source, msg string, ts time.Time) {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return
	}
	if len(msg) > 400 {
		msg = msg[:400]
	}
	key := level + "|" + source + "|" + normalizeMsg(msg)
	evMu.Lock()
	e, ok := evIndex[key]
	if ok {
		e.Count++
		e.Last = ts
		e.Msg = msg
	} else {
		e = &event{Level: level, Source: source, Msg: msg, Count: 1, First: ts, Last: ts, key: key}
		evIndex[key] = e
		events = append(events, e)
		if n := *fMaxEvents; n > 0 && len(events) > n {
			drop := events[0]
			events = events[1:]
			delete(evIndex, drop.key)
		}
	}
	snapshotOfEvent := *e
	evMu.Unlock()
	if !ok {
		appendJSONL(eventFile, snapshotOfEvent)
	}
}

func normalizeMsg(s string) string {
	var b strings.Builder
	prevDigit := false
	for _, r := range s {
		if r >= '0' && r <= '9' {
			if !prevDigit {
				b.WriteByte('#')
			}
			prevDigit = true
			continue
		}
		prevDigit = false
		b.WriteRune(r)
	}
	return b.String()
}

func eventsSnapshot() []event {
	evMu.Lock()
	defer evMu.Unlock()
	out := make([]event, 0, len(events))
	for _, e := range events {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Last.After(out[j].Last) })
	return out
}

func countEvents(level string) int {
	evMu.Lock()
	defer evMu.Unlock()
	n := 0
	for _, e := range events {
		if e.Level == level {
			n += e.Count
		}
	}
	return n
}

// ---------- хранение на диске ----------

func persistSample(s *snapshot) {
	if *fPersist <= 0 || statsFile == "" {
		return
	}
	if time.Since(lastSaved) < time.Duration(*fPersist)*time.Second {
		return
	}
	lastSaved = time.Now()
	row := map[string]any{"t": s.At.Unix(), "ifaces": s.Ifaces}
	if s.Hub != nil {
		row["hubTotals"] = s.Hub.Totals
		users := make([]map[string]any, 0, len(s.Hub.Users))
		for _, u := range s.Hub.Users {
			users = append(users, map[string]any{
				"name": u.Name, "inner": u.Inner, "peer": u.Peer, "online": u.Online,
				"pktIn": u.PktIn, "pktOut": u.PktOut, "bytesIn": u.BytesIn, "bytesOut": u.BytesOut,
			})
		}
		row["hubUsers"] = users
	}
	appendJSONL(statsFile, row)
	if devs := devSnapshot(s.At); len(devs) > 0 {
		appendJSONL(devFile, map[string]any{"t": s.At.Unix(), "devices": devs})
	}
}

func appendJSONL(path string, v any) {
	if path == "" {
		return
	}
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	rotateIfBig(path)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return
	}
	defer f.Close()
	f.Write(append(b, '\n'))
}

func rotateIfBig(path string) {
	max := int64(*fMaxLog) * 1024 * 1024
	if max <= 0 {
		return
	}
	st, err := os.Stat(path)
	if err != nil || st.Size() < max {
		return
	}
	os.Remove(path + ".1")
	os.Rename(path, path+".1")
}

// ---------- форматирование ----------

func fmtBytes(n uint64) string {
	f := float64(n)
	units := []string{"Б", "КиБ", "МиБ", "ГиБ", "ТиБ"}
	i := 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d %s", n, units[i])
	}
	return fmt.Sprintf("%.1f %s", f, units[i])
}

func fmtRate(bps float64) string {
	if bps < 1 {
		return "0"
	}
	return fmtBytes(uint64(bps)) + "/с"
}

func fmtNum(n uint64) string {
	s := strconv.FormatUint(n, 10)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	lead := len(s) % 3
	if lead > 0 {
		b.WriteString(s[:lead])
	}
	for i := lead; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(s[i : i+3])
	}
	return b.String()
}

func fmtAge(sec int64) string {
	if sec < 0 {
		return "нет"
	}
	if sec < 60 {
		return strconv.FormatInt(sec, 10) + " с"
	}
	if sec < 3600 {
		return strconv.FormatInt(sec/60, 10) + " мин"
	}
	if sec < 86400 {
		return strconv.FormatInt(sec/3600, 10) + " ч"
	}
	return strconv.FormatInt(sec/86400, 10) + " сут"
}
