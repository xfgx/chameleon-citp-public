def edit(path, pairs):
    s = open(path, encoding='utf-8').read()
    for old, new, cnt in pairs:
        n = s.count(old)
        assert n == cnt, f'{path}: anchor {n}!={cnt}: {old[:70]!r}'
        s = s.replace(old, new, cnt)
    open(path, 'w', encoding='utf-8').write(s)
    print(f'{path}: OK ({len(pairs)} anchors)')

tab = chr(9)
nl = chr(10)

# ---------- cmd/ks-vpn/main.go ----------
f = 'cmd/ks-vpn/main.go'
edit(f, [
    # счётчик времени последнего валидного ответа
    (tab + 'cLoopGuard atomic.Uint64 // отброшено петлестопом (пакеты к проводному IP ноды)',
     tab + 'cLoopGuard atomic.Uint64 // отброшено петлестопом (пакеты к проводному IP ноды)' + nl + tab + 'lastRxUnix atomic.Int64 // время последней валидной датаграммы (unix; 0 = не было)', 1),
    # флаг -peertunip
    (tab + 'fullTun := flag.Bool("fulltun", false, "полный VPN (Windows-клиент): сам настроить маршруты — обходной /32 до ноды + сплит /1 в туннель + /32 до приватных DNS; по Ctrl+C снять")',
     tab + 'fullTun := flag.Bool("fulltun", false, "полный VPN (Windows-клиент): сам настроить маршруты — обходной /32 до ноды + сплит /1 в туннель + /32 до приватных DNS; по Ctrl+C снять")' + nl + tab + 'peerTun := flag.String("peertunip", "", "туннельный IP ноды для keepalive (пусто = тот же /24, хост .2)")', 1),
    # keepalive-блок перед логгером счётчиков
    (tab + '// логгер счётчиков',
     tab + '// keepalive (только клиентская роль): ICMP echo ноде сквозь туннель каждые' + nl + tab + '// 15с — держит NAT-дыру открытой и даёт индикатор канала (lastRx в стадиях).' + nl + tab + 'var ownTun4, peerTun4 net.IP' + nl + tab + 'if ip, _, err := net.ParseCIDR(*tunIP); err == nil {' + nl + tab + tab + 'ownTun4 = ip.To4()' + nl + tab + '}' + nl + tab + 'if *peerTun != "" {' + nl + tab + tab + 'peerTun4 = net.ParseIP(*peerTun).To4()' + nl + tab + '} else if ownTun4 != nil {' + nl + tab + tab + 'peerTun4 = net.IPv4(ownTun4[0], ownTun4[1], ownTun4[2], 2) // нода по конвенции .2' + nl + tab + '}' + nl + tab + 'if *peerHost != "" && ownTun4 != nil && peerTun4 != nil {' + nl + tab + tab + 'go func() {' + nl + tab + tab + tab + 'tk := time.NewTicker(15 * time.Second)' + nl + tab + tab + tab + 'var seq uint16' + nl + tab + tab + tab + 'for range tk.C {' + nl + tab + tab + tab + tab + 'seq++' + nl + tab + tab + tab + tab + 'tx.TickEpoch(time.Now())' + nl + tab + tab + tab + tab + 'wire := tx.Seal(icmpEcho(ownTun4, peerTun4, kaID, seq))' + nl + tab + tab + tab + tab + 'dst := peerAddr(*peerHost, *peerPort)' + nl + tab + tab + tab + tab + 'if dst == nil {' + nl + tab + tab + tab + tab + tab + 'continue' + nl + tab + tab + tab + tab + '}' + nl + tab + tab + tab + tab + 'if _, err := sock.WriteToUDP(wire, dst); err == nil {' + nl + tab + tab + tab + tab + tab + 'cSent.Add(1)' + nl + tab + tab + tab + tab + '}' + nl + tab + tab + tab + '}' + nl + tab + tab + '}()' + nl + tab + '}' + nl + nl + tab + '// логгер счётчиков', 1),
    # перехват keepalive-ответов + отметка lastRx
    (tab + tab + tab + 'cIngestOK.Add(1)' + nl + tab + tab + tab + 'if pkt.src != nil {' + nl + tab + tab + tab + tab + 'lastPeer.Store(pkt.src) // учим адрес только от валидных датаграмм' + nl + tab + tab + tab + '}' + nl + tab + tab + tab + 'cTunWrite.Add(1)',
     tab + tab + tab + 'cIngestOK.Add(1)' + nl + tab + tab + tab + 'lastRxUnix.Store(time.Now().Unix())' + nl + tab + tab + tab + 'if pkt.src != nil {' + nl + tab + tab + tab + tab + 'lastPeer.Store(pkt.src) // учим адрес только от валидных датаграмм' + nl + tab + tab + tab + '}' + nl + tab + tab + tab + 'if ownTun4 != nil && isKaReply(plain, ownTun4) {' + nl + tab + tab + tab + tab + 'continue // наш keepalive-ответ — в TUN не пишем' + nl + tab + tab + tab + '}' + nl + tab + tab + tab + 'cTunWrite.Add(1)', 1),
    # строка стадий: +lastRx
    ('стадии: tunRd=%d sent=%d udpRecv=%d ingestOK=%d dropped=%d tunWr=%d loop=%d',
     'стадии: tunRd=%d sent=%d udpRecv=%d ingestOK=%d dropped=%d tunWr=%d loop=%d lastRx=%s', 1),
    ('cTunRead.Load(), cSent.Load(), cUdpRecv.Load(), cIngestOK.Load(), cDropped.Load(), cTunWrite.Load(), cLoopGuard.Load())',
     'cTunRead.Load(), cSent.Load(), cUdpRecv.Load(), cIngestOK.Load(), cDropped.Load(), cTunWrite.Load(), cLoopGuard.Load(), lastRxStr())', 1),
    # функция lastRxStr перед peerAddr
    ('// peerAddr — куда слать:',
     '// lastRxStr — читаемый возраст последнего валидного ответа ("15s" / "нет").' + nl + 'func lastRxStr() string {' + nl + tab + 't := lastRxUnix.Load()' + nl + tab + 'if t == 0 {' + nl + tab + tab + 'return "нет"' + nl + tab + '}' + nl + tab + 'return strconv.Itoa(int(time.Since(time.Unix(t, 0)).Seconds())) + "s"' + nl + '}' + nl + nl + '// peerAddr — куда слать:', 1),
])

# ---------- cmd/ks-vpn/tun_windows.go ----------
f = 'cmd/ks-vpn/tun_windows.go'
edit(f, [
    (tab + '"os/exec"' + nl + tab + '"time"',
     tab + '"os/exec"' + nl + tab + '"strings"' + nl + tab + '"time"', 1),
    (tab + 'return &wtun{ad: ad, session: sess}, name, nil',
     tab + '// MTU как у ноды (1300): иначе большие TLS-пакеты фрагментировались бы в провод' + nl + tab + 'if out, e3 := exec.Command("netsh", "interface", "ipv4", "set", "subinterface",' + nl + tab + tab + 'name, "mtu=1300", "store=active").CombinedOutput(); e3 != nil {' + nl + tab + tab + 'log.Printf("netsh mtu 1300 на %s: %v (%s)", name, e3, strings.TrimSpace(string(out)))' + nl + tab + '}' + nl + tab + 'return &wtun{ad: ad, session: sess}, name, nil', 1),
])

# ---------- cmd/ks-vpn/fulltun_windows.go ----------
f = 'cmd/ks-vpn/fulltun_windows.go'
edit(f, [
    (tab + 'if !ok {' + nl + tab + tab + 'log.Printf("fulltun: НЕ все маршруты встали',
     tab + '// проверка, что правило брандмауэра реально на месте' + nl + tab + 'if out, err := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name=ks-vpn-in").CombinedOutput(); err != nil {' + nl + tab + tab + 'log.Printf("fulltun: правило брандмауэра НЕ найдено (%v, %s) — входящие ответы могут резаться", err, strings.TrimSpace(string(out)))' + nl + tab + '}' + nl + tab + '// есть ли IPv6-дефолт: v4-туннель его не захватывает — честное предупреждение' + nl + tab + 'if out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",' + nl + tab + tab + '"(Get-NetRoute -DestinationPrefix \'::/0\' -ErrorAction SilentlyContinue | Measure-Object).Count").Output(); err == nil {' + nl + tab + tab + 'if c := strings.TrimSpace(string(out)); c != "0" && c != "" {' + nl + tab + tab + tab + 'log.Printf("fulltun: ВНИМАНИЕ: у тебя есть IPv6-дефолт — v6-трафик пойдёт мимо туннеля напрямую (ограничение v4-туннеля; если что-то поломается — скажи, добавим нейтрализацию)")' + nl + tab + tab + '}' + nl + tab + '}' + nl + tab + 'if !ok {' + nl + tab + tab + 'log.Printf("fulltun: НЕ все маршруты встали', 1),
])
print('PATCH_V4_DONE')
