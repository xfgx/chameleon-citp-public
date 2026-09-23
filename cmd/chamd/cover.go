package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"sync"
	"time"
)

// Cover — переработанный генератор прикрывающего и легендированного трафика.
//
// Новая концепция:
// 1. Полная рандомизация:
//    - Никаких фиксированных интервалов или циклических паттернов.
//    - Случайные паузы с распределением Пуассона / логнормальным (от 4 до 85 секунд).
//    - Варьирование TLS ClientHello SNI, заголовков, User-Agent, размеров запрашиваемых фрагментов.
// 2. Минимально-существующие и прерываемые запросы (Decoy / Phantom Connections):
//    - Режим "Abort-on-Handshake": отправка TLS ClientHello, завершение handshake и немедленный RST/Close сокета (DPI видит начало валидной HTTPS-сессии, но полезная нагрузка не тратится).
//    - Режим "Early-Cut / Partial": считывание первых 100-800 байт ответа и резкий сброс соединения (имитация передумавшего пользователя / фонового пинга).
//    - Режим "HEAD / Range-probe": минимальный GET с `Range: bytes=0-255` или HEAD-запрос.
// 3. Провайдер и ТСПУ видят постоянную фоновую активность к разным серверам РФ/RU-сегмента, но трафик не расходуется впустую и выглядит абсолютно органично и хаотично.

type coverTarget struct {
	Name string
	Host string
	Port string
	Path string
}

var coverTargets = []coverTarget{
	{"VK-API", "api.vk.com", "443", "/method/stats.trackEvents"},
	{"VK-Feed", "vk.com", "443", "/feed"},
	{"VK-Video", "vkvideo.ru", "443", "/"},
	{"Yandex-Gate", "ya.ru", "443", "/"},
	{"Yandex-Weather", "yandex.ru", "443", "/pogoda"},
	{"Dzen", "dzen.ru", "443", "/"},
	{"Mail.ru", "mail.ru", "443", "/"},
	{"OK.ru", "ok.ru", "443", "/"},
	{"Rutube", "rutube.ru", "443", "/api/play/options/"},
	{"Kinopoisk", "www.kinopoisk.ru", "443", "/"},
	{"Gosuslugi-Portal", "www.gosuslugi.ru", "443", "/api/nsi/v1/dictionary"},
	{"WB-Static", "www.wildberries.ru", "443", "/"},
	{"Ozon-Catalog", "www.ozon.ru", "443", "/"},
	{"Sber-Online", "www.sberbank.ru", "443", "/portalserver/static/version.json"},
	{"Avito", "www.avito.ru", "443", "/"},
	{"T-Bank", "www.tbank.ru", "443", "/"},
	{"Steam-Store", "store.steampowered.com", "443", "/"},
	{"Steam-Community", "steamcommunity.com", "443", "/"},
	{"Steam-API", "api.steampowered.com", "443", "/ISteamWebAPIUtil/GetServerInfo/v1/"},
	{"Selectel-Edge", "selectel.ru", "443", "/"},
	{"Habr-Feed", "habr.com", "443", "/ru/all/"},
	{"Rambler", "www.rambler.ru", "443", "/"},
}

var realisticUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 YaBrowser/24.12.0.0 Yowser/2.5 Safari/537.36",
	"Valve/Steam HTTP Client 1.0 (Windows;10.0.22631)",
}

type Cover struct {
	m      *Manager
	client *http.Client
	stopCh chan struct{}
	once   sync.Once

	// Прямой обход туннеля (критично для TUN-режима): без host-route /32
	// cover-запросы заворачиваются ВНУТРЬ шифрованного туннеля — провайдер
	// не видит легенды, а нода расходует канал на мусор.
	bypassAdd func(ip string)     // nil в не-TUN режиме (там и так напрямую)
	mu        sync.Mutex          // защищает pinned/bypassed
	pinned    map[string][]string // host → IP, разрешённые ДО поднятия TUN
	bypassed  map[string]bool     // IP, для которых маршрут уже добавлен
}

func NewCover(m *Manager) *Cover {
	c := &Cover{
		m:        m,
		stopCh:   make(chan struct{}),
		pinned:   make(map[string][]string),
		bypassed: make(map[string]bool),
	}
	// DialContext с пиннингом: дозвон идёт на заранее разрешённый IP,
	// а SNI/Host остаются настоящим доменом — для DPI это честная сессия
	// к настоящему сервису, но маршрутизируется она по нашему обходу.
	c.client = &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true, // каждый раз новая TLS сессия для чистоты паттерна
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if host, port, err := net.SplitHostPort(addr); err == nil {
					if ip := c.pinnedIP(host); ip != "" {
						addr = net.JoinHostPort(ip, port)
					}
				}
				return (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, network, addr)
			},
		},
	}
	return c
}

// SetBypassAdder подключает обход туннеля (TunDevice.AddCoverBypass).
// Вызывать только в TUN-режиме.
func (c *Cover) SetBypassAdder(fn func(ip string)) { c.bypassAdd = fn }

// pinTargets резолвит все cover-домены СИСТЕМНЫМ DNS до поднятия туннеля
// (прямой резолв → правдоподобные RU-адреса, а не CDN-нода нашей ноды)
// и запоминает пары host→IP.
func (c *Cover) pinTargets() {
	for _, t := range coverTargets {
		if _, ok := c.pinned[t.Host]; ok {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", t.Host)
		cancel()
		if err != nil || len(ips) == 0 {
			continue
		}
		list := make([]string, 0, len(ips))
		for _, ip := range ips {
			list = append(list, ip.String())
		}
		c.pinned[t.Host] = list
	}
}

// pinnedIP выбирает закреплённый IP хоста и регистрирует обходной маршрут.
// Пустая строка = нет пина (запрос уйдёт обычным путём).
func (c *Cover) pinnedIP(host string) string {
	c.mu.Lock()
	ips := c.pinned[host]
	if len(ips) == 0 {
		c.mu.Unlock()
		return ""
	}
	ip := ips[rand.IntN(len(ips))]
	already := c.bypassed[ip]
	if !already {
		c.bypassed[ip] = true
	}
	add := c.bypassAdd
	c.mu.Unlock()
	if !already && add != nil {
		add(ip) // host-route /32 через физический шлюз — мимо туннеля
	}
	return ip
}

func (c *Cover) Start() {
	// Пиним ДО того, как TUN перехватит DNS и маршруты.
	c.pinTargets()
	go func() {
		for {
			// Экспоненциально-рандомизированный интервал (без предсказуемого шага)
			// От 4 до 65 секунд с пиками активности (bursts)
			pause := 4 + rand.IntN(20)
			if rand.IntN(5) == 0 { // редкие длинные паузы сёрфинга (20-60 с)
				pause += 15 + rand.IntN(45)
			}

			select {
			case <-c.stopCh:
				return
			case <-time.After(time.Duration(pause) * time.Second):
			}

			if !c.m.Status().Active {
				continue
			}

			c.fireRandomizedDecoy()
		}
	}()
}

func (c *Cover) Stop() {
	c.once.Do(func() {
		close(c.stopCh)
	})
}

// fireRandomizedDecoy запускает один из 3 вариантов легендированного сетевого взаимодействия:
// 1. Abort-Handshake: Только TLS ClientHello -> ServerHello -> немедленный сброс сокета
// 2. Partial Range/Cut: HTTP GET с быстрым прерыванием после первых 128..512 байт
// 3. Micro Probe: Минимальный HEAD / GET запрос
func (c *Cover) fireRandomizedDecoy() {
	target := coverTargets[rand.IntN(len(coverTargets))]
	mode := rand.IntN(3)

	switch mode {
	case 0:
		// Режим 1: TLS Handshake & Immediate Abort (минимальнейший footprint)
		go c.doTLSAbortHandshake(target)
	case 1:
		// Режим 2: Partial HTTP GET с прерыванием
		go c.doPartialCutRequest(target)
	default:
		// Режим 3: Micro Range-запрос
		go c.doMicroProbeRequest(target)
	}
}

func (c *Cover) doTLSAbortHandshake(target coverTarget) {
	// Пиннинг: дозвон на закреплённый IP (идёт по обходному маршруту
	// мимо TUN), SNI — настоящий домен.
	dialHost := target.Host
	if ip := c.pinnedIP(target.Host); ip != "" {
		dialHost = ip
	}
	addr := net.JoinHostPort(dialHost, target.Port)
	dialer := &net.Dialer{Timeout: 4 * time.Second}
	rawConn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return
	}
	defer rawConn.Close()

	tlsConfig := &tls.Config{
		ServerName:         target.Host,
		InsecureSkipVerify: true,
	}
	tlsConn := tls.Client(rawConn, tlsConfig)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	if err := tlsConn.HandshakeContext(ctx); err == nil {
		// Handshake успешно завершен в глазах ТСПУ/провайдера!
		// Сразу же закрываем сокет без передачи HTTP данных (DPI фиксирует валидное начало сессии)
		_ = tlsConn.Close()
		c.m.logf("legend: [TLS-Decoy] %s (Handshake OK -> Aborted)", target.Host)
	}
}

func (c *Cover) doPartialCutRequest(target coverTarget) {
	url := fmt.Sprintf("https://%s%s", target.Host, target.Path)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return
	}

	req.Header.Set("User-Agent", realisticUserAgents[rand.IntN(len(realisticUserAgents))])
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "ru-RU,ru;q=0.9,en;q=0.8")
	req.Header.Set("Sec-Fetch-Mode", "navigate")

	resp, err := c.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Считываем всего 128..512 байт ответа и РЕЗКО обрываем (io.LimitReader + Close)
	cutLimit := int64(128 + rand.IntN(384))
	n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, cutLimit))
	c.m.logf("legend: [Partial-Cut] %s -> %d (%d B read -> Cut)", target.Host, resp.StatusCode, n)
}

func (c *Cover) doMicroProbeRequest(target coverTarget) {
	url := fmt.Sprintf("https://%s%s", target.Host, target.Path)
	method := http.MethodHead
	if rand.IntN(2) == 0 {
		method = http.MethodGet
	}

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return
	}

	req.Header.Set("User-Agent", realisticUserAgents[rand.IntN(len(realisticUserAgents))])
	if method == http.MethodGet {
		// Запрашиваем только первые 64 байта через HTTP Range
		req.Header.Set("Range", "bytes=0-63")
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	c.m.logf("legend: [Micro-Probe %s] %s -> %d", method, target.Host, resp.StatusCode)
}

// RotateDecoys пересобирает пины decoy-целей (очистка + повторный резолв).
// Вызывается автопилотом при обнаружении HTTP-заглушки провайдера.
func (c *Cover) RotateDecoys() {
	c.mu.Lock()
	c.pinned = make(map[string][]string)
	c.bypassed = make(map[string]bool)
	c.mu.Unlock()
	c.pinTargets()
	c.m.logf("legend: decoy-цели ротированы (%d хостов в пуле)", len(coverTargets))
}
