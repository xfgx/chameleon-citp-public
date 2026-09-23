//go:build linux

// Веб-интерфейс панели: страница входа, дашборд и JSON-API.
// Все таблицы готовятся на сервере, браузер только рисует.
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type apiCard struct {
	Label string `json:"label"`
	Value string `json:"value"`
	Sub   string `json:"sub,omitempty"`
	Tone  string `json:"tone,omitempty"`
}

type apiRow struct {
	Cells []string `json:"c"`
	Level string   `json:"lvl,omitempty"`
}

type apiTable struct {
	Title string   `json:"title"`
	Head  []string `json:"head"`
	Rows  []apiRow `json:"rows"`
	Note  string   `json:"note,omitempty"`
}

type apiStats struct {
	At      string     `json:"at"`
	Version string     `json:"version"`
	Uptime  string     `json:"uptime"`
	Cards   []apiCard  `json:"cards"`
	Tables  []apiTable `json:"tables"`
}

func serve() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/logout", handleLogout)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"ok": true, "version": adminVersion})
	})
	mux.HandleFunc("/api/stats", requireAuth(handleAPIStats))
	mux.HandleFunc("/api/events", requireAuth(handleAPIEvents))
	mux.HandleFunc("/api/hist", requireAuth(handleAPIHist))
	mux.HandleFunc("/", requireAuth(handleDash))

	srv := &http.Server{
		Addr:              *fListen,
		Handler:           secHeaders(mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       90 * time.Second,
	}
	if !*fTLS {
		return srv.ListenAndServe()
	}
	cert, err := ensureCert(filepath.Join(*fDataDir, "tls"))
	if err != nil {
		return err
	}
	srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	return srv.ListenAndServeTLS("", "")
}

func secHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'")
		h.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// ---------- API: сводка ----------

func handleAPIStats(w http.ResponseWriter, r *http.Request) {
	out := apiStats{Version: adminVersion, Uptime: fmtAge(int64(time.Since(startedAt).Seconds()))}
	s := snap.Load()
	if s == nil {
		writeJSON(w, out)
		return
	}
	out.At = s.At.Local().Format("02.01.2006 15:04:05")

	var totRx, totTx, totRxP, totTxP uint64
	var rate float64
	for _, f := range s.Ifaces {
		totRx += f.RxBytes
		totTx += f.TxBytes
		totRxP += f.RxPkts
		totTxP += f.TxPkts
		rate += f.RxRate + f.TxRate
	}
	online, users := 0, 0
	if s.Hub != nil {
		users = len(s.Hub.Users)
		for _, u := range s.Hub.Users {
			if u.Online {
				online++
			}
		}
	}
	devices := map[string]bool{}
	for _, c := range s.Conns {
		devices[c.Src] = true
	}
	errs, warns := countEvents("ERROR"), countEvents("WARN")
	errTone := "ok"
	if warns > 0 {
		errTone = "warn"
	}
	if errs > 0 {
		errTone = "bad"
	}
	out.Cards = []apiCard{
		{Label: "Пользователи хаба", Value: fmt.Sprintf("%d / %d", online, users), Sub: "онлайн из выданных", Tone: "ok"},
		{Label: "Активные адреса", Value: fmtNum(uint64(len(devices))), Sub: "устройств на проводе сейчас"},
		{Label: "Проброшено трафика", Value: fmtBytes(totRx + totTx), Sub: "в туннель " + fmtBytes(totTx) + " / из туннеля " + fmtBytes(totRx)},
		{Label: "Пакетов", Value: fmtNum(totRxP + totTxP), Sub: "вх " + fmtNum(totRxP) + " / исх " + fmtNum(totTxP)},
		{Label: "Сейчас", Value: fmtRate(rate), Sub: "суммарно по туннелям"},
		{Label: "Ошибки / предупреждения", Value: fmt.Sprintf("%d / %d", errs, warns), Sub: "с момента запуска панели", Tone: errTone},
	}

	out.Tables = []apiTable{
		tableHubUsers(s),
		tableDevices(s),
		tableDevLog(),
		tableIfaces(s),
		tableServices(s),
	}
	writeJSON(w, out)
}

func tableHubUsers(s *snapshot) apiTable {
	t := apiTable{
		Title: "Пользователи многопользовательского хаба",
		Head:  []string{"Имя", "Внутренний IP", "Устройство (адрес:порт)", "Состояние", "Последний приём", "Пакеты вх / исх", "Трафик вх / исх"},
	}
	if s.Hub == nil {
		t.Note = "хаб недоступен: " + s.HubErr
		return t
	}
	users := make([]hubUser, len(s.Hub.Users))
	copy(users, s.Hub.Users)
	sort.Slice(users, func(i, j int) bool {
		if users[i].Online != users[j].Online {
			return users[i].Online
		}
		return users[i].Slot < users[j].Slot
	})
	for _, u := range users {
		state, lvl := "офлайн", ""
		if u.Online {
			state, lvl = "онлайн", "ok"
		}
		peer := u.Peer
		if peer == "" {
			peer = "-"
		}
		t.Rows = append(t.Rows, apiRow{Level: lvl, Cells: []string{
			u.Name, u.Inner, peer, state, fmtAge(u.LastRxSec),
			fmtNum(u.PktIn) + " / " + fmtNum(u.PktOut),
			fmtBytes(u.BytesIn) + " / " + fmtBytes(u.BytesOut),
		}})
	}
	if len(t.Rows) == 0 {
		t.Note = "пользователи ещё не выданы (ks_user.sh add имя)"
	} else if s.Hub.Isolate {
		t.Note = "изоляция клиентов включена: пользователи не видят друг друга"
	}
	return t
}

type devKey struct {
	svc string
	src string
}

type devAgg struct {
	ports map[int]bool
	pkts  uint64
	byts  uint64
	port  int
}

func tableDevices(s *snapshot) apiTable {
	t := apiTable{
		Title: "Устройства на проводе",
		Head:  []string{"Служба", "Адрес устройства", "Портов источника", "Порт узла", "Пакетов", "Трафик"},
		Note:  "живые соединения прямо сейчас (запись живёт около 30 с после последнего пакета). Видны только адреса и объёмы - содержимое трафика не собирается",
	}
	agg := map[devKey]*devAgg{}
	for _, c := range s.Conns {
		k := devKey{svc: c.Service, src: c.Src}
		a, ok := agg[k]
		if !ok {
			a = &devAgg{ports: map[int]bool{}, port: c.Port}
			agg[k] = a
		}
		a.ports[c.Sport] = true
		a.pkts += c.Packets
		a.byts += c.Bytes
	}
	type row struct {
		k devKey
		a *devAgg
	}
	rows := make([]row, 0, len(agg))
	for k, a := range agg {
		rows = append(rows, row{k, a})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].a.byts != rows[j].a.byts {
			return rows[i].a.byts > rows[j].a.byts
		}
		return rows[i].a.pkts > rows[j].a.pkts
	})
	for i, r := range rows {
		if i >= 40 {
			break
		}
		bytesCell := fmtBytes(r.a.byts)
		pktCell := fmtNum(r.a.pkts)
		if r.a.byts == 0 && r.a.pkts == 0 {
			bytesCell, pktCell = "учёт выкл.", "учёт выкл."
		}
		t.Rows = append(t.Rows, apiRow{Cells: []string{
			r.k.svc, r.k.src, strconv.Itoa(len(r.a.ports)), strconv.Itoa(r.a.port), pktCell, bytesCell,
		}})
	}
	if len(t.Rows) == 0 {
		t.Note = "активных соединений нет; содержимое трафика не собирается"
	}
	return t
}

func tableDevLog() apiTable {
	t := apiTable{
		Title: "Журнал устройств",
		Head:  []string{"Служба", "Адрес устройства", "Состояние", "Первый раз", "Последняя активность", "Портов", "Пакетов", "Трафик"},
		Note:  "все адреса, замеченные с момента запуска панели; полная история - в /var/lib/ks-admin/devices.jsonl",
	}
	now := time.Now()
	for i, d := range devSnapshot(now) {
		if i >= 60 {
			break
		}
		state, lvl := "офлайн", ""
		if d.Active {
			state, lvl = "активно", "ok"
		}
		bytesCell, pktCell := fmtBytes(d.Bytes), fmtNum(d.Pkts)
		if d.Bytes == 0 && d.Pkts == 0 {
			bytesCell, pktCell = "-", "-"
		}
		t.Rows = append(t.Rows, apiRow{Level: lvl, Cells: []string{
			d.Svc, d.Src, state,
			time.Unix(d.First, 0).Local().Format("02.01 15:04"),
			time.Unix(d.Last, 0).Local().Format("02.01 15:04:05"),
			strconv.Itoa(d.Ports), pktCell, bytesCell,
		}})
	}
	if len(t.Rows) == 0 {
		t.Note = "устройств пока не зафиксировано"
	}
	return t
}

func tableIfaces(s *snapshot) apiTable {
	t := apiTable{
		Title: "Туннели",
		Head:  []string{"Интерфейс", "Состояние", "Принято", "Передано", "Пакеты вх / исх", "Сейчас", "Ошибки", "Потери"},
	}
	for _, f := range s.Ifaces {
		state, lvl := "нет", "bad"
		if f.Up {
			state, lvl = "активен", "ok"
		}
		if f.RxErrs+f.TxErrs > 0 {
			lvl = "warn"
		}
		t.Rows = append(t.Rows, apiRow{Level: lvl, Cells: []string{
			f.Name, state, fmtBytes(f.RxBytes), fmtBytes(f.TxBytes),
			fmtNum(f.RxPkts) + " / " + fmtNum(f.TxPkts),
			fmtRate(f.RxRate) + " \u2193 " + fmtRate(f.TxRate) + " \u2191",
			fmtNum(f.RxErrs + f.TxErrs), fmtNum(f.RxDrop + f.TxDrop),
		}})
	}
	return t
}

func tableServices(s *snapshot) apiTable {
	t := apiTable{
		Title: "Службы",
		Head:  []string{"Служба", "Состояние", "Из туннеля", "Зашифровано", "UDP принято", "Расшифровано", "В туннель", "Отброшено", "Последний приём"},
	}
	for _, v := range s.Svcs {
		state, lvl := "остановлена", "bad"
		if v.Active {
			state, lvl = "работает", "ok"
		}
		n := v.Nums
		lastRx := v.LastRxSec
		if s.Hub != nil && strings.Contains(v.Unit, "hub") {
			n = map[string]uint64{
				"tunRd":    s.Hub.Totals["tunRead"],
				"sent":     s.Hub.Totals["sent"],
				"udpRecv":  s.Hub.Totals["udpRecv"],
				"ingestOK": s.Hub.Totals["ingestOK"],
				"tunWr":    s.Hub.Totals["tunWrite"],
				"dropped":  s.Hub.Totals["dropped"],
			}
			lastRx = -1
			for _, u := range s.Hub.Users {
				if u.LastRxSec >= 0 && (lastRx < 0 || u.LastRxSec < lastRx) {
					lastRx = u.LastRxSec
				}
			}
		}
		if n == nil {
			n = map[string]uint64{}
		}
		if n["dropped"] > 0 && lvl == "ok" {
			lvl = "warn"
		}
		t.Rows = append(t.Rows, apiRow{Level: lvl, Cells: []string{
			v.Unit, state,
			fmtNum(n["tunRd"]), fmtNum(n["sent"]), fmtNum(n["udpRecv"]),
			fmtNum(n["ingestOK"]), fmtNum(n["tunWr"]), fmtNum(n["dropped"]),
			fmtAge(lastRx),
		}})
	}
	t.Note = "счётчики старых служб берутся из их журнала, хаб - из его status.json"
	return t
}

// ---------- API: ошибки ----------

func handleAPIEvents(w http.ResponseWriter, r *http.Request) {
	t := apiTable{
		Title: "Ошибки и предупреждения",
		Head:  []string{"Уровень", "Источник", "Сообщение", "Повторов", "Последний раз"},
	}
	only := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("level")))
	for i, e := range eventsSnapshot() {
		if i >= 200 {
			break
		}
		if only != "" && e.Level != only {
			continue
		}
		lvl := ""
		switch e.Level {
		case "ERROR":
			lvl = "bad"
		case "WARN":
			lvl = "warn"
		}
		t.Rows = append(t.Rows, apiRow{Level: lvl, Cells: []string{
			e.Level, e.Source, e.Msg, fmtNum(uint64(e.Count)),
			e.Last.Local().Format("02.01 15:04:05"),
		}})
	}
	if len(t.Rows) == 0 {
		t.Note = "ошибок и предупреждений не зафиксировано"
	}
	writeJSON(w, map[string]any{"table": t})
}

// ---------- API: история скорости ----------

func handleAPIHist(w http.ResponseWriter, r *http.Request) {
	pts := histSnapshot()
	vals := make([]float64, 0, len(pts))
	peak := 0.0
	for _, p := range pts {
		tot := 0.0
		for _, v := range p.Rate {
			tot += v
		}
		if tot > peak {
			peak = tot
		}
		vals = append(vals, tot)
	}
	writeJSON(w, map[string]any{
		"values":   vals,
		"peak":     peak,
		"peakText": fmtRate(peak),
		"stepSec":  *fInterval,
	})
}

// ---------- страницы ----------

func handleDash(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	page := strings.ReplaceAll(dashHTML, "{{VERSION}}", html.EscapeString(adminVersion))
	page = strings.ReplaceAll(page, "{{USER}}", html.EscapeString(conf.User))
	_, _ = w.Write([]byte(page))
}

func renderLogin(w http.ResponseWriter, msg string, status int, csrf string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	banner := ""
	if msg != "" {
		banner = `<div class="msg">` + html.EscapeString(msg) + `</div>`
	}
	page := strings.ReplaceAll(loginHTML, "{{MSG}}", banner)
	page = strings.ReplaceAll(page, "{{VERSION}}", html.EscapeString(adminVersion))
	page = strings.ReplaceAll(page, "{{CSRF}}", html.EscapeString(csrf))
	_, _ = w.Write([]byte(page))
}

const baseCSS = `
:root{--bg:#0B0B0D;--card:#151518;--line:#242429;--acc:#8B5CF6;--acc2:#60A5FA;--fg:#FAFAFA;--mut:#A1A1AA;--bad:#F87171;--warn:#FBBF24;--ok:#34D399}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Ubuntu,sans-serif;-webkit-text-size-adjust:100%}
a{color:var(--acc2)}
header{position:sticky;top:0;z-index:5;display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between;padding:12px 16px;background:rgba(11,11,13,.92);border-bottom:1px solid var(--line);backdrop-filter:blur(8px)}
header h1{margin:0;font-size:17px;font-weight:650;letter-spacing:.2px}
.sub{color:var(--mut);font-size:12px}
.btn{display:inline-block;padding:8px 14px;border-radius:10px;border:1px solid var(--line);background:var(--card);color:var(--fg);text-decoration:none;font-size:13px;cursor:pointer}
.btn:hover{border-color:var(--acc)}
main{padding:16px;max-width:1180px;margin:0 auto}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin-bottom:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:14px 16px}
.card .lbl{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.4px}
.card .val{font-size:24px;font-weight:680;margin-top:6px;word-break:break-word}
.card .sub{color:var(--mut);font-size:12px;margin-top:4px}
.card.ok .val{color:var(--ok)}.card.warn .val{color:var(--warn)}.card.bad .val{color:var(--bad)}
section.block{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:14px 16px;margin-bottom:14px}
section.block h2{margin:0 0 10px;font-size:15px;font-weight:640}
.note{color:var(--mut);font-size:12px;margin:0 0 8px}
.scroll{overflow-x:auto;-webkit-overflow-scrolling:touch}
table{border-collapse:collapse;width:100%;min-width:520px;font-size:13px}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap}
th{color:var(--mut);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.4px}
td:nth-child(3){white-space:normal}
tr.ok td:nth-child(4),tr.ok td:nth-child(2){color:var(--ok)}
tr.warn td:first-child{color:var(--warn)}
tr.bad td:first-child{color:var(--bad)}
.privacy{border:1px dashed var(--line);border-radius:12px;padding:10px 12px;color:var(--mut);font-size:12px;margin-bottom:14px}
svg.spark{width:100%;height:64px;display:block}
footer{color:var(--mut);font-size:11px;text-align:center;padding:18px 8px 28px}
@media(max-width:560px){.card .val{font-size:20px}main{padding:12px}header{padding:10px 12px}}
`

const loginHTML = `<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>KS-VPN - вход в панель</title>
<style>` + baseCSS + `
.wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
form{width:100%;max-width:360px;background:var(--card);border:1px solid var(--line);border-radius:18px;padding:22px}
form h1{margin:0 0 4px;font-size:19px}
label{display:block;color:var(--mut);font-size:12px;margin:14px 0 6px}
input{width:100%;padding:11px 12px;border-radius:10px;border:1px solid var(--line);background:#0F0F12;color:var(--fg);font-size:15px}
input:focus{outline:none;border-color:var(--acc)}
button{width:100%;margin-top:18px;padding:12px;border:0;border-radius:12px;background:var(--acc);color:#fff;font-size:15px;font-weight:600;cursor:pointer}
.msg{margin-top:14px;padding:10px 12px;border-radius:10px;background:#2A1414;border:1px solid #4C1D1D;color:var(--bad);font-size:13px}
</style></head>
<body><div class="wrap"><form method="post" action="/login" autocomplete="off">
<input type="hidden" name="csrf" value="{{CSRF}}">
<h1>Панель администратора</h1>
<div class="sub">KS-VPN · RU-нода</div>
<label for="user">Логин</label>
<input id="user" name="user" required autocapitalize="none" autocorrect="off">
<label for="pass">Пароль</label>
<input id="pass" name="pass" type="password" required>
<button type="submit">Войти</button>
{{MSG}}
<div class="privacy" style="margin-top:18px">Панель показывает только статистику и ошибки. Содержимое трафика не собирается.</div>
<div class="sub" style="margin-top:10px">{{VERSION}}</div>
</form></div></body></html>
`

const dashHTML = `<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>KS-VPN - панель администратора</title>
<style>` + baseCSS + `</style></head>
<body>
<header>
  <div><h1>KS-VPN · панель администратора</h1><div class="sub" id="meta">загрузка...</div></div>
  <div style="display:flex;gap:8px;align-items:center">
    <span class="sub">{{USER}}</span>
    <a class="btn" href="/logout">Выйти</a>
  </div>
</header>
<main>
  <div class="privacy">Собирается только статистика: адреса устройств, счётчики пакетов/трафика и сообщения об ошибках. Сам интернет-трафик не читается и не хранится.</div>
  <div class="cards" id="cards"></div>
  <section class="block"><h2>Скорость по всем туннелям</h2><p class="note" id="sparkNote"></p><div id="spark"></div></section>
  <div id="tables"></div>
  <div id="eventsBox"></div>
</main>
<footer id="foot">{{VERSION}}</footer>
<script>
function mk(tag,cls,txt){var e=document.createElement(tag);if(cls)e.className=cls;if(txt!==undefined)e.textContent=txt;return e}
function renderCards(cards){
  var box=document.getElementById('cards');box.textContent='';
  (cards||[]).forEach(function(c){
    var d=mk('div','card'+(c.tone?' '+c.tone:''));
    d.appendChild(mk('div','lbl',c.label));
    d.appendChild(mk('div','val',c.value));
    if(c.sub)d.appendChild(mk('div','sub',c.sub));
    box.appendChild(d);
  });
}
function renderTable(t){
  var s=mk('section','block');
  s.appendChild(mk('h2',null,t.title));
  if(t.note)s.appendChild(mk('p','note',t.note));
  if(t.rows&&t.rows.length){
    var sc=mk('div','scroll'),tb=mk('table'),hr=mk('tr');
    (t.head||[]).forEach(function(h){hr.appendChild(mk('th',null,h))});
    tb.appendChild(hr);
    t.rows.forEach(function(r){
      var tr=mk('tr',r.lvl||null);
      (r.c||[]).forEach(function(v){tr.appendChild(mk('td',null,v))});
      tb.appendChild(tr);
    });
    sc.appendChild(tb);s.appendChild(sc);
  }
  return s;
}
function renderSpark(h){
  var box=document.getElementById('spark');box.textContent='';
  var v=h.values||[];
  document.getElementById('sparkNote').textContent='пик '+(h.peakText||'0')+' · шаг '+(h.stepSec||5)+' с · точек '+v.length;
  if(v.length<2)return;
  var max=Math.max.apply(null,v)||1,W=600,H=64,step=W/(v.length-1),d='';
  for(var i=0;i<v.length;i++){var x=(i*step).toFixed(1),y=(H-(v[i]/max)*(H-4)-2).toFixed(1);d+=(i?'L':'M')+x+','+y}
  var ns='http://www.w3.org/2000/svg';
  var svg=document.createElementNS(ns,'svg');
  svg.setAttribute('class','spark');svg.setAttribute('viewBox','0 0 '+W+' '+H);svg.setAttribute('preserveAspectRatio','none');
  var area=document.createElementNS(ns,'path');
  area.setAttribute('d',d+'L'+W+','+H+'L0,'+H+'Z');area.setAttribute('fill','rgba(139,92,246,.18)');
  var line=document.createElementNS(ns,'path');
  line.setAttribute('d',d);line.setAttribute('fill','none');line.setAttribute('stroke','#8B5CF6');line.setAttribute('stroke-width','2');
  svg.appendChild(area);svg.appendChild(line);box.appendChild(svg);
}
async function get(u){
  var r=await fetch(u,{headers:{'Accept':'application/json'}});
  if(r.status===401){location.href='/login';throw new Error('auth')}
  if(!r.ok)throw new Error(u+': '+r.status);
  return r.json();
}
async function load(){
  try{
    var res=await Promise.all([get('/api/stats'),get('/api/events'),get('/api/hist')]);
    var s=res[0],e=res[1],h=res[2];
    document.getElementById('meta').textContent='обновлено '+(s.at||'-')+' · панель работает '+(s.uptime||'-');
    document.getElementById('foot').textContent=s.version||'';
    renderCards(s.cards);
    renderSpark(h);
    var box=document.getElementById('tables');box.textContent='';
    (s.tables||[]).forEach(function(t){box.appendChild(renderTable(t))});
    var eb=document.getElementById('eventsBox');eb.textContent='';
    if(e&&e.table)eb.appendChild(renderTable(e.table));
  }catch(err){
    document.getElementById('meta').textContent='ошибка обновления: '+err.message;
  }
}
load();setInterval(load,5000);
</script>
</body></html>
`
