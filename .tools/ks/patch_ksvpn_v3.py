import sys

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
f = 'cmd/ks-vpn/main.go'

edit(f, [
    # imports: +os, +os/signal, +runtime
    (tab + '"net"' + nl + tab + '"strconv"',
     tab + '"net"' + nl + tab + '"os"' + nl + tab + '"os/signal"' + nl + tab + '"runtime"' + nl + tab + '"strconv"', 1),
    # счётчик петлестопа
    (tab + 'cTunWrite atomic.Uint64 // IP-пакетов записано в TUN' + nl + ')',
     tab + 'cTunWrite atomic.Uint64 // IP-пакетов записано в TUN' + nl + tab + 'cLoopGuard atomic.Uint64 // отброшено петлестопом (пакеты к проводному IP ноды)' + nl + ')', 1),
    # флаг -fulltun
    (tab + 'rotT := flag.Uint64("T", 8, "период ротации эпох, сек (одинаковый на обеих сторонах)")',
     tab + 'rotT := flag.Uint64("T", 8, "период ротации эпох, сек (одинаковый на обеих сторонах)")' + nl + tab + 'fullTun := flag.Bool("fulltun", false, "полный VPN (Windows-клиент): сам настроить маршруты — обходной /32 до ноды + сплит /1 в туннель + /32 до приватных DNS; по Ctrl+C снять")', 1),
    # peerIP4 для петлестопа — после проверки tunip
    (tab + 'if *tunIP == "" {' + nl + tab + tab + 'log.Fatal("нужен -tunip (туннельный IP/CIDR)")' + nl + tab + '}',
     tab + 'if *tunIP == "" {' + nl + tab + tab + 'log.Fatal("нужен -tunip (туннельный IP/CIDR)")' + nl + tab + '}' + nl + nl + tab + '// проводной IP ноды — для петлестопа (ниже)' + nl + tab + 'var peerIP4 net.IP' + nl + tab + 'if *peerHost != "" {' + nl + tab + tab + 'peerIP4 = net.ParseIP(*peerHost).To4()' + nl + tab + tab + 'if peerIP4 == nil {' + nl + tab + tab + tab + 'log.Printf("внимание: -peerhost %q не IPv4 — петлестоп выключен", *peerHost)' + nl + tab + tab + '}' + nl + tab + '}', 1),
    # fulltun-блок после строки про слушатель
    (tab + 'log.Printf("слушаю UDP :%d; исходящее -> %s:%d", *listenPort, *peerHost, *peerPort)',
     tab + 'log.Printf("слушаю UDP :%d; исходящее -> %s:%d", *listenPort, *peerHost, *peerPort)' + nl + nl + tab + '// полный VPN (Windows-клиент): маршруты ставим сами, по Ctrl+C — снимаем' + nl + tab + 'if *fullTun && runtime.GOOS == "windows" {' + nl + tab + tab + 'cleanup := setupFullTun(*peerHost, *tunIP, *listenPort)' + nl + tab + tab + 'sigc := make(chan os.Signal, 2)' + nl + tab + tab + 'signal.Notify(sigc, os.Interrupt)' + nl + tab + tab + 'go func() {' + nl + tab + tab + tab + '<-sigc' + nl + tab + tab + tab + 'cleanup()' + nl + tab + tab + tab + 'os.Exit(0)' + nl + tab + tab + '}()' + nl + tab + '}', 1),
    # формат строки счётчиков: +loop
    ('стадии: tunRd=%d sent=%d udpRecv=%d ingestOK=%d dropped=%d tunWr=%d',
     'стадии: tunRd=%d sent=%d udpRecv=%d ingestOK=%d dropped=%d tunWr=%d loop=%d', 1),
    ('cTunRead.Load(), cSent.Load(), cUdpRecv.Load(), cIngestOK.Load(), cDropped.Load(), cTunWrite.Load())',
     'cTunRead.Load(), cSent.Load(), cUdpRecv.Load(), cIngestOK.Load(), cDropped.Load(), cTunWrite.Load(), cLoopGuard.Load())', 1),
    # петлестоп в цикле tun->net
    (tab + tab + 'cTunRead.Add(1)' + nl + tab + tab + 'tx.TickEpoch(time.Now())',
     tab + tab + 'cTunRead.Add(1)' + nl + tab + tab + '// петлестоп: пакеты к проводному IP ноды в туннель НЕ входят — иначе' + nl + tab + tab + '// провод туннеля заглатывает сам себя (полевой взрыв счётчиков 2026-09-01).' + nl + tab + tab + 'if peerIP4 != nil && n >= 20 && buf[0]>>4 == 4 && net.IP(buf[16:20]).Equal(peerIP4) {' + nl + tab + tab + tab + 'cLoopGuard.Add(1)' + nl + tab + tab + tab + 'continue' + nl + tab + tab + '}' + nl + tab + tab + 'tx.TickEpoch(time.Now())', 1),
])
print('PATCH_V3_DONE')
