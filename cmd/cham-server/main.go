package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"chameleon/internal/chameleon"
)

// cham-server — серверное ПО ноды Chameleon VPN (протокол v2).
//
// Ставится на ваш VPS. Поведение:
//  1. Принимает TCP, ждёт аутентифицированное рукопожатие (72 байта
//     мусора снаружи; расшифровать их может только владелец ключа ноды).
//  2. Зонд/мусор/replay → НИ БАЙТА ответа: соединение уходит в blackhole
//     (молча поглощается до таймаута). Нода неотличима от мёртвого сервиса.
//  3. IP с серией провалов аутентификации попадает в strike-list и
//     blackhole'ится сразу, без траты CPU на криптографию.
//  4. Валидный сеанс: мультиплексор потоков + опциональный CBR-шейпинг.
//
// Первый запуск: сгенерируйте ключ ноды и сообщите ПУБЛИЧНЫЙ клиентам:
//
//	cham-server -genkey -keyfile /root/cham-server.key
//
// Запуск:
//
//	cham-server -listen 0.0.0.0:8443 -keyfile /root/cham-server.key -cbr 40ms
func main() {
	listen := flag.String("listen", "0.0.0.0:9443", "адрес прослушивания")
	keyfile := flag.String("keyfile", "cham-server.key", "файл приватного ключа ноды")
	genkey := flag.Bool("genkey", false, "сгенерировать ключ ноды, показать публичный и выйти")
	cbr := flag.Duration("cbr", 0, "интервал CBR-паддинга (0 = выкл), напр. 40ms")
	flavorName := flag.String("flavor", "auto", "маска ритма: auto, vk-video, rutube, kinopoisk, vk-feed, yandex, sber, gosuslugi, wb-ozon, mail, steam-dl, steam-app")
	dialTimeout := flag.Duration("dial-timeout", 10*time.Second, "таймаут подключения к цели")
	hold := flag.Duration("blackhole", 45*time.Second, "сколько держать blackhole-соединение")
	allowfile := flag.String("allowfile", "", "файл белого списка клиентов (base64-ключ на строку; пустой = принимать всех)")
	maxConnections := flag.Int("max-connections", 1024, "максимум одновременных подключений")
	policyFile := flag.String("policy", "", "JSON-файл единой egress policy (пустой = безопасная policy по умолчанию)")
	cfListen := flag.String("cf-listen", "", "Control Fabric HTTPS bulletin listen address (empty = disabled), e.g. 0.0.0.0:9444")
	cfCARListen := flag.String("cf-car-listen", "", "Control Fabric CAR HTTP listen address (empty = disabled), e.g. 0.0.0.0:9445")
	cfDNSListen := flag.String("cf-dns-listen", "", "Control Fabric DNS beacon UDP listen address (empty = disabled), e.g. 0.0.0.0:5353")
	cfPublicHost := flag.String("cf-public-host", "", "public host/IP advertised in Control Fabric hints; empty = auto-detect node IP")
	cfSeed := flag.String("cf-seed", "", "Control Fabric seed; empty = derived from node private key")
	cfBoardURL := flag.String("cf-board-url", "", "external bulletin board base URL (e.g. https://<worker>.workers.dev); control frames are mirrored there, so the board survives a node IP block. Write token is read from env CITP_CF_BOARD_TOKEN")
	cfCARTrigger := flag.String("cf-car-trigger", "", "файл триггер-сигнатур CAR trigger-host (одна на строку, # — комментарии; пустой = benign lab-токен). Настоящие сигнатуры — данные оператора, в код не зашиваются")
	cfSchedule := flag.Bool("cf-schedule", true, "этап F: привязка control-сообщений к эпохам + расписание порядка каналов и окон CAR из DRBG (false = legacy-формат для отката; клиент и нода должны совпадать)")
	upstream := flag.String("upstream", "", "каскад: адрес вышестоящей (зарубежной) ноды host:port; весь egress идёт через неё, fail-closed")
	upstreamPub := flag.String("upstream-pubkey", "", "каскад: публичный ключ вышестоящей ноды (base64)")
	upstreamKey := flag.String("upstream-clientkey", "/root/cham-upstream.key", "каскад: файл клиентского ключа этой ноды для вышестоящей (генерируется при отсутствии)")
	upstreamDirect := flag.String("upstream-direct", "", "каскад: файл доменных суффиксов для прямого дозвона мимо цепочки (одна строка = один суффикс)")
	wsListen := flag.String("ws-listen", "", "WS-фронт (CDN-фронтинг): WebSocket listen для воркера Cloudflare (пустой = выкл), напр. 0.0.0.0:9446")
	wsToken := flag.String("ws-token", "", "WS-фронт: токен пути /b/<token>; пустой = детерминированный из ключа ноды (печатается в журнал)")
	ttlsListen := flag.String("ttls-listen", "", "TTLS-фронт (CITP v3.0 Sub-Horizon): UDP listen для фантомных кадров клиентов, напр. 0.0.0.0:55353 (пустой = выкл)")
	ttlsSecret := flag.String("ttls-secret", "", "TTLS-фронт: общий с клиентами секрет (PSK); пустой = детерминированный из ключа ноды (печатается в журнал)")
	cfThetaBroadcast := flag.Bool("cf-theta-broadcast", true, "слои 6/8: рассылка θ-распределения и карты дорогих зон по борду (по handshake и на смену эпохи)")
	cfThetaFile := flag.String("cf-theta-file", "", "JSON-файл θ-распределения оператора (пустой = DefaultTheta)")
	cfCollateralAS := flag.String("cf-collateral-as", "", "ASN зоны для карты дорогих зон (пустой = unknown)")
	flag.Parse()
	if *maxConnections < 1 || *maxConnections > 65536 {
		log.Fatal("-max-connections должен быть в диапазоне 1..65536")
	}

	if *genkey {
		privB64, pubB64, err := chameleon.GenerateNodeKey()
		if err != nil {
			log.Fatal(err)
		}
		if err := chameleon.SaveNodeKey(*keyfile, privB64); err != nil {
			log.Fatal(err)
		}
		log.Printf("ключ ноды записан в %s (0600)", *keyfile)
		log.Printf("ПУБЛИЧНЫЙ КЛЮЧ (дать клиентам, в панель): %s", pubB64)
		return
	}

	priv, err := chameleon.LoadNodeKey(*keyfile)
	if err != nil {
		log.Fatalf("нет ключа ноды: %v (сначала: cham-server -genkey -keyfile %s)", err, *keyfile)
	}

	allow, accessErr := newClientAccess(*allowfile)
	if accessErr != nil { log.Fatalf("allowlist: refusing to start without valid access policy: %v", accessErr) }
	watchClientAccess(allow)
	if *allowfile != "" {
		log.Printf("белый список клиентов: %d ключей из %s", len(allow.snapshot()), *allowfile)
	} else {
		log.Printf("ВНИМАНИЕ: белый список не задан — принимаются все, кто знает ключ ноды")
	}

	policy := chameleon.DefaultPolicy()
	if *policyFile != "" {
		b, err := os.ReadFile(*policyFile)
		if err != nil {
			log.Fatalf("policy %s: %v", *policyFile, err)
		}
		decoder := json.NewDecoder(bytes.NewReader(b))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&policy); err != nil {
			log.Fatalf("policy %s: %v", *policyFile, err)
		}
		if err := decoder.Decode(&struct{}{}); err != io.EOF {
			log.Fatalf("policy %s: trailing JSON", *policyFile)
		}
	}
	policyEngine := chameleon.NewPolicyEngine(policy)

	cf, cfClosers := startControlFabric(*cfListen, *cfCARListen, *cfDNSListen, *cfPublicHost, *cfSeed, *cfBoardURL, *cfCARTrigger, *cfSchedule, priv)
	defer func() {
		for _, closeFn := range cfClosers {
			closeFn()
		}
	}()
	if cf != nil {
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
	}

	// TTLS-фронт (CITP v3.0): фантомные UDP-кадры клиентов с ограниченным TTL.
	// Независим от TCP-слушателя и боевого :9443; отвечает эхом для проверки канала.
	if *ttlsListen != "" {
		if err := startTTLSFront(*ttlsListen, *ttlsSecret, priv); err != nil {
			log.Fatalf("ttls-фронт: %v", err)
		}
	}

	// Каскад нода→нода: egress через вышестоящую (зарубежную) ноду, fail-closed.
	var chain *chameleon.UpstreamChain
	if *upstream != "" {
		if *upstreamPub == "" {
			log.Fatal("-upstream требует -upstream-pubkey")
		}
		privB64, err := loadOrGenClientKey(*upstreamKey)
		if err != nil {
			log.Fatalf("chain client key: %v", err)
		}
		chainPriv, err := chameleon.ParseNodePrivKey(privB64)
		if err != nil {
			log.Fatalf("chain client key: %v", err)
		}
		chain, err = chameleon.NewUpstreamChain(*upstream, *upstreamPub, chainPriv, loadSignalLines(*upstreamDirect))
		if err != nil {
			log.Fatalf("chain: %v", err)
		}
		chain.Start()
		defer chain.Close()
		log.Printf("каскад: вышестоящая нода %s; наш клиентский pubkey (добавить в её allowlist, если тот включён): %s", *upstream, chain.ClientPubB64())
	}

	strikes := newStrikeList()
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("cham-server v2: нода слушает %s (cbr=%v, blackhole=%v, max-connections=%d)", *listen, *cbr, *hold, *maxConnections)
	connections := make(chan struct{}, *maxConnections)

	// WS-фронт (CDN-фронтинг): воркер Cloudflare ретранслирует сюда клиентские
	// потоки — для DPI клиент соединяется с IP CDN, нода в трафике не видна.
	// Снаружи порт выглядит пустым веб-сервером: без верного токена пути — 404.
	if *wsListen != "" {
		tok := *wsToken
		if tok == "" {
			sum := sha256.Sum256(append(priv.Bytes(), []byte(":ws-front")...))
			tok = hex.EncodeToString(sum[:12])
		}
		log.Printf("ws-фронт: слушаю %s, путь /b/%s", *wsListen, tok)
		muxWS := http.NewServeMux()
		muxWS.HandleFunc("/b/", func(w http.ResponseWriter, r *http.Request) {
			c, err := chameleon.AcceptWS(w, r, tok)
			if err != nil {
				return // AcceptWS уже ответил 404
			}
			select {
			case connections <- struct{}{}:
				go func() {
					defer func() { <-connections }()
					handle(c, priv, allow, strikes, policyEngine, cf, chain, *cbr, *dialTimeout, *flavorName, *hold)
				}()
			default:
				_ = c.Close()
			}
		})
		go func() {
			if err := http.ListenAndServe(*wsListen, muxWS); err != nil {
				log.Printf("ws-фронт: %v", err)
			}
		}()
	}

	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		select {
		case connections <- struct{}{}:
			go func() {
				defer func() { <-connections }()
				handle(c, priv, allow, strikes, policyEngine, cf, chain, *cbr, *dialTimeout, *flavorName, *hold)
			}()
		default:
			_ = c.Close()
		}
	}
}

// loadOrGenClientKey читает клиентский ключ каскада из файла; при отсутствии
// генерирует и сохраняет (0600) — личность ноды-клиента переживает рестарты.
func loadOrGenClientKey(path string) (string, error) {
	if b, err := os.ReadFile(path); err == nil {
		if s := strings.TrimSpace(string(b)); s != "" {
			return s, nil
		}
	}
	privB64, _, err := chameleon.GenerateNodeKey()
	if err != nil {
		return "", err
	}
	if err := chameleon.SaveNodeKey(path, privB64); err != nil {
		return "", err
	}
	return privB64, nil
}

// loadSignalLines читает файл с одной сигнатурой на строку (# — комментарии).
// Пустой путь или отсутствующий файл = nil (benign lab-режим).
func loadSignalLines(path string) []string {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		log.Printf("cf-car-trigger: %v", err)
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// loadAllowlist читает белый список клиентских публичных ключей
// (одна base64-строка на ключ, # — комментарии). Пустой путь или
// отсутствующий файл = список пуст (принимать всех).
func loadAllowlist(path string) map[[32]byte]bool {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		log.Printf("allowfile %s: %v — принимаю всех", path, err)
		return nil
	}
	allow := make(map[[32]byte]bool)
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pub, err := chameleon.ParseNodePubKey(line)
		if err != nil {
			log.Printf("allowfile: пропускаю невалидный ключ %q: %v", line, err)
			continue
		}
		var k [32]byte
		copy(k[:], pub.Bytes())
		allow[k] = true
	}
	return allow
}

// strikeList — in-memory учёт IP с провалами аутентификации.
type strikeList struct {
	mu sync.Mutex
	m  map[string]*strike
}

type strike struct {
	fails    int
	lastFail time.Time
}

func newStrikeList() *strikeList { return &strikeList{m: make(map[string]*strike)} }

func (s *strikeList) hit(ip string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.m) >= 65536 {
		cutoff := time.Now().Add(-10 * time.Minute)
		for key, value := range s.m {
			if value.lastFail.Before(cutoff) {
				delete(s.m, key)
			}
		}
		if len(s.m) >= 65536 {
			for key := range s.m {
				delete(s.m, key)
				break
			}
		}
	}
	st := s.m[ip]
	if st == nil {
		st = &strike{}
		s.m[ip] = st
	}
	// Полураспад: 10 минут без провалов — счётчик обнуляется.
	if time.Since(st.lastFail) > 10*time.Minute {
		st.fails = 0
	}
	st.fails++
	st.lastFail = time.Now()
	return st.fails
}

func (s *strikeList) get(ip string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st := s.m[ip]; st != nil && time.Since(st.lastFail) <= 10*time.Minute {
		return st.fails
	}
	return 0
}

func ipOf(c net.Conn) string {
	if host, _, err := net.SplitHostPort(c.RemoteAddr().String()); err == nil {
		return host
	}
	return c.RemoteAddr().String()
}

func handle(c net.Conn, priv *ecdh.PrivateKey, allow *clientAccess, strikes *strikeList, policy *chameleon.PolicyEngine, cf *chameleon.ControlFabric, chain *chameleon.UpstreamChain, cbr, dialTimeout time.Duration, flavorName string, hold time.Duration) {
	defer c.Close()
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	ip := ipOf(c)

	// Серийный сканер: сразу в blackhole, криптографию даже не считаем.
	if n := strikes.get(ip); n >= 5 {
		log.Printf("blackhole: %s (забанен, провалов: %d)", ip, n)
		chameleon.Blackhole(c, hold)
		return
	}

	sess, clientPub, err := chameleon.ServerHandshake(c, priv, allow.snapshot())
	if err != nil {
		if err == chameleon.ErrAuth {
			// Зонд, мусор, replay или чужое устройство: молчим, ни байта ответа.
			if n := strikes.hit(ip); n >= 3 {
				log.Printf("blackhole: %s (провалов аутентификации: %d)", ip, n)
			}
			chameleon.Blackhole(c, hold)
		}
		return
	}
	if !allow.register(c, clientPub) { return }
	defer allow.unregister(c)
	conn, err := chameleon.NewServerConn(c, sess)
	if err != nil {
		return
	}
	log.Printf("сеанс установлен с %s (клиент …%s)", ip, base64.RawURLEncoding.EncodeToString(clientPub)[36:])
	if cf != nil {
		sessionID := chameleon.ControlSessionID(clientPub)
		if err := cf.PublishControl(context.Background(), sessionID, chameleon.ControlBootstrapHint()); err != nil {
			log.Printf("control-fabric publish failed for %s: %v", ip, err)
		}
		// Слои 6/8: клиенту сразу уезжают θ и карта дорогих зон (свои каналы борда).
		if thetaBC != nil {
			sessReg.Add(clientPub)
			thetaBC.PublishTo(clientPub, time.Now())
		}
	}

	if cbr > 0 {
		f := chameleon.FlavorByName(flavorName, nil)
		sh := conn.StartShaper(f.Base, f.Jitter, f.MinPad, f.MaxPad, "s2c-cbr")
		defer sh.Stop()
	}
	// Мультиплексор: все потоки клиента внутри одного сеанса.
	if chain != nil {
		chameleon.ServeMuxWithEgress(conn, dialTimeout, policy, nil, chain.Dial, chain.DialUDP)
		return
	}
	chameleon.ServeMuxWithPolicy(conn, dialTimeout, policy, nil)
}

func startControlFabric(cdnListen, carListen, dnsListen, publicHost, seedText, boardURL, carTriggerFile string, scheduleOn bool, priv *ecdh.PrivateKey) (*chameleon.ControlFabric, []func()) {
	var cdn *chameleon.CDNCacheStateChannel
	var car *chameleon.CARChannel
	var dns *chameleon.DNSBeacon
	var closers []func()
	if publicHost == "" {
		publicHost = autodetectNodeIP()
	}
	if seedText == "" && priv != nil {
		seedText = base64.RawURLEncoding.EncodeToString(priv.Bytes())
	}
	seed := []byte("chameleon-control-fabric:" + seedText)
	var board *chameleon.RemoteBoard
	if boardURL != "" {
		token := os.Getenv("CITP_CF_BOARD_TOKEN")
		if token == "" {
			log.Printf("control-fabric: WARNING -cf-board-url is set but CITP_CF_BOARD_TOKEN is empty; the board will reject writes")
		}
		board = chameleon.NewRemoteBoard(boardURL, token)
		closers = append(closers, func() { board.Close() })
		log.Printf("control-fabric: external bulletin board %s (control frames mirrored off-node)", boardURL)
	}
	if cdnListen != "" || board != nil {
		cdn = chameleon.NewCDNCacheStateChannel(cdnListen)
		if board != nil {
			cdn.WithRemoteBoard(board)
		}
		if cdnListen != "" {
			if publicHost != "" {
				if err := cdn.WithTLS(publicHost); err != nil {
					log.Printf("control-fabric cdn tls disabled: %v", err)
				}
			}
			go func() {
				if err := cdn.Serve(); err != nil {
					log.Printf("control-fabric cdn stopped: %v", err)
				}
			}()
			closers = append(closers, func() { _ = cdn.Shutdown() })
		}
	}
	if carListen != "" {
		car = chameleon.NewCARChannel(carListen)
		// Этап B1 (trigger-host): набор триггер-сигнатур — конфигурация
		// оператора из файла; без файла нода отдаёт только benign lab-токен.
		if sigs := loadSignalLines(carTriggerFile); len(sigs) > 0 {
			car.WithTriggerSignatures(sigs)
			log.Printf("control-fabric car: trigger-host, %d сигнатур оператора из %s", len(sigs), carTriggerFile)
		} else if carTriggerFile != "" {
			log.Printf("control-fabric car: WARNING файл триггеров %s пуст/нечитаем — откат на benign токен", carTriggerFile)
		}
		go func() {
			if err := car.Serve(); err != nil {
				log.Printf("control-fabric car stopped: %v", err)
			}
		}()
		closers = append(closers, func() { _ = car.Shutdown() })
	}
	if dnsListen != "" {
		dns = chameleon.NewDNSBeacon(dnsListen, "cf.chameleon.node", "c", 5)
		go func() {
			if err := dns.Serve(); err != nil {
				log.Printf("control-fabric dns stopped: %v", err)
			}
		}()
		closers = append(closers, func() { _ = dns.Close() })
	}
	if cdn == nil && car == nil && dns == nil {
		return nil, closers
	}
	chameleon.SetControlFabricNodeHint(publicHost, cdnListen, carListen, dnsListen)
	if boardURL != "" {
		chameleon.SetControlFabricBoardURL(boardURL)
	}
	cf := chameleon.NewControlFabric(seed, cdn, car, dns, nil)
	if scheduleOn {
		// Этап F: расписание эпох из DRBG(secret‖модель‖эпоха) — привязка
		// сообщений к эпохам (анти-replay), смещение окон CAR, перестановка
		// порядка каналов. Модель — каноническая v1 (одинакова у клиентов).
		cf.WithSchedule(nil, 0)
		log.Printf("control-fabric: этап F включён (расписание эпох, модель v1, эпоха %v)", chameleon.DefaultScheduleEpochLen)
	}
	return cf, closers
}

func autodetectNodeIP() string {
	// Adaptive: discover this node's primary routable IPv4 at runtime
	// (CITP_NODE_IP overrides; UDP-route trick with interface fallback).
	return chameleon.DetectNodeIP()
}

// startTTLSFront поднимает UDP-приёмник Sub-Horizon TTL Smuggling (CITP v3.0).
// Каждый подлинный кадр клиента логируется и эхом возвращается отправителю.
// Пустой PSK детерминированно выводится из ключа ноды (как токен WS-фронта).
func startTTLSFront(listenAddr, secret string, priv *ecdh.PrivateKey) error {
	if secret == "" {
		sum := sha256.Sum256(append(priv.Bytes(), []byte(":ttls-front")...))
		secret = hex.EncodeToString(sum[:16])
		log.Printf("ttls-фронт: PSK не задан, использую производный: %s", secret)
	}
	sm, err := chameleon.NewTTLSmuggler(secret)
	if err != nil {
		return err
	}
	recv, err := chameleon.NewTTLReceiver(sm, listenAddr)
	if err != nil {
		return err
	}
	log.Printf("ttls-фронт: слушаю UDP %s (Sub-Horizon TTL Smuggling)", recv.LocalAddr())
	go func() {
		for {
			fr, err := recv.ReadFrame()
			if err != nil {
				log.Printf("ttls-фронт: %v", err)
				return
			}
			log.Printf("ttls-фронт: кадр от %s seq=%d ttl=%d size=%d", fr.Src, fr.Seq, fr.TTL, fr.Size)
			echo := append([]byte("echo:"), fr.Payload...)
			if _, err := recv.SendTo(fr.Src, fr.Seq, echo, 64); err != nil {
				log.Printf("ttls-фронт: ответ %s: %v", fr.Src, err)
			}
		}
	}()
	return nil
}
