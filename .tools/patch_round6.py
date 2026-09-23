#!/usr/bin/env python3
# Раунд 6: кастомные порты слушателей chamd (занят -> следующий свободный,
# :0 -> ОС) + реестр фактических адресов в Status панели.
import sys

SK = "/files/VPN/cmd/chamd/socks.go"
WB = "/files/VPN/cmd/chamd/web.go"
DN = "/files/VPN/cmd/chamd/dns.go"
MG = "/files/VPN/cmd/chamd/manager.go"
MN = "/files/VPN/cmd/chamd/main.go"

EDITS = []

EDITS.append((SK, """	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Printf("chamd: SOCKS5 слушает %s", addr)""", """	ln, actual, err := listenTCP(m, addr, "SOCKS5")
	if err != nil {
		return err
	}
	m.SetListenAddr("socks", actual)
	log.Printf("chamd: SOCKS5 слушает %s", actual)"""))

EDITS.append((WB, """	return http.ListenAndServe(addr, mux)""", """	ln, actual, err := listenTCP(m, addr, "панель")
	if err != nil {
		return err
	}
	m.SetListenAddr("ui", actual)
	log.Printf("chamd: панель слушает http://%s", actual)
	return http.Serve(ln, mux)"""))

EDITS.append((DN, """	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Printf("dns: %v (TUN-резолв не заведётся)", err)
		return
	}
	log.Printf("chamd: DNS-резолвер на %s → %s через туннель", addr, dnsUpstream)""", """	pc, actual, err := listenUDP(m, addr, "DNS")
	if err != nil {
		log.Printf("dns: %v (TUN-резолв не заведётся)", err)
		return
	}
	m.SetListenAddr("dns", actual)
	if actual != addr {
		log.Printf("dns: ВНИМАНИЕ: %s занят, резолвер на %s; TUN-режим ожидает 127.0.0.1:53", addr, actual)
	}
	log.Printf("chamd: DNS-резолвер на %s → %s через туннель", actual, dnsUpstream)"""))

EDITS.append((MG, """	onSessionUp   func()            // хук «сеанс поднят» (зовётся асинхронно; слой 3: выжившие канарейки)""", """	onSessionUp   func()            // хук «сеанс поднят» (зовётся асинхронно; слой 3: выжившие канарейки)

	// Реестр фактических адресов слушателей (раунд 6: кастомные порты).
	listenMu    sync.Mutex
	listenAddrs map[string]string"""))

EDITS.append((MG, """		pinMap:     make(map[string]string),
	}""", """		pinMap:      make(map[string]string),
		listenAddrs: make(map[string]string),
	}"""))

EDITS.append((MG, """// SetOnSessionUp регистрирует колбэк на успешный подъём сеанса (автопилот).
func (m *Manager) SetOnSessionUp(fn func()) { m.onSessionUp = fn }""", """// SetOnSessionUp регистрирует колбэк на успешный подъём сеанса (автопилот).
func (m *Manager) SetOnSessionUp(fn func()) { m.onSessionUp = fn }

// SetListenAddr запоминает фактический адрес слушателя: порт мог быть
// подобран автоматически (раунд 6) — панель показывает, куда реально встали
// SOCKS5/панель/DNS.
func (m *Manager) SetListenAddr(name, addr string) {
	m.listenMu.Lock()
	defer m.listenMu.Unlock()
	m.listenAddrs[name] = addr
}"""))

EDITS.append((MG, """	// Автопилот:
	DoHMode  bool   `json:"doh_mode"`            // резолв нод через DoH (перехват DNS)
	AutoNote string `json:"auto_note,omitempty"` // последнее действие автопилота
}""", """	// Автопилот:
	DoHMode  bool   `json:"doh_mode"`            // резолв нод через DoH (перехват DNS)
	AutoNote string `json:"auto_note,omitempty"` // последнее действие автопилота
	// Фактические адреса слушателей (раунд 6: порт мог быть подобран автоматически):
	Listen map[string]string `json:"listen,omitempty"`
}"""))

EDITS.append((MG, """	if st.Active {
		st.Since = m.activeSince.Format("15:04:05")
	}""", """	m.listenMu.Lock()
	if len(m.listenAddrs) > 0 {
		st.Listen = make(map[string]string, len(m.listenAddrs))
		for k, v := range m.listenAddrs {
			st.Listen[k] = v
		}
	}
	m.listenMu.Unlock()
	if st.Active {
		st.Since = m.activeSince.Format("15:04:05")
	}"""))

EDITS.append((MN, """	ui := flag.String("ui", "127.0.0.1:8080", "адрес панели управления")
	socks := flag.String("socks", "127.0.0.1:1080", "адрес SOCKS5")""", """	ui := flag.String("ui", "127.0.0.1:8080", "адрес панели управления (порт занят → подберётся свободный; :0 = выбор ОС)")
	socks := flag.String("socks", "127.0.0.1:1080", "адрес SOCKS5 (порт занят → подберётся свободный; :0 = выбор ОС)")"""))

EDITS.append((MN, """	dnsAddr := flag.String("dns", "127.0.0.1:53", "адрес DNS-резолвера через туннель (на Android: 127.0.0.1:5353)")""", """	dnsAddr := flag.String("dns", "127.0.0.1:53", "адрес DNS-резолвера через туннель (на Android: 127.0.0.1:5353; порт занят → подберётся свободный)")"""))

contents = {}
for path, old, _new in EDITS:
    if path not in contents:
        with open(path, encoding="utf-8") as f:
            contents[path] = f.read()

for path, old, new in EDITS:
    src = contents[path]
    n = src.count(old)
    if n != 1:
        print("FATAL: якорь встречается %d раз (нужно 1) в %s:\n%s" % (n, path, old[:140]))
        sys.exit(1)
    contents[path] = src.replace(old, new)

# web.go: log.Printf в serveUI — нужен импорт log.
wb = contents[WB]
if '\t"log"\n' not in wb:
    if "import (\n" not in wb:
        print("FATAL: web.go: не найден блок import")
        sys.exit(1)
    contents[WB] = wb.replace("import (\n", "import (\n\t\"log\"\n", 1)
    print("web.go: добавлен импорт log")

for path, text in contents.items():
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    print("PATCHED", path)
