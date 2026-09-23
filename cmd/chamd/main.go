package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

// chamd — клиентский демон Chameleon VPN (Windows 11).
//
//  1. Панель управления на http://127.0.0.1:8080 — сервера, подключение, журнал.
//  2. Автоподхват трафика:
//     -tun      — TUN-адаптер Wintun (нужен admin + wintun.dll рядом с exe);
//     весь TCP системы идёт в туннель автоматически.
//     -sysproxy — иначе: системный прокси Windows на SOCKS5 (без admin).
//  3. Cover-трафик: фоновые РЕАЛЬНЫЕ запросы к российским сервисам,
//     чтобы с нашего IP шёл не только «мусор» туннеля.
//
// Запуск:
//
//	chamd.exe -tun                    (от администратора, wintun.dll рядом)
//	chamd.exe                         (без admin: системный прокси + SOCKS5)
func main() {
	ui := flag.String("ui", "127.0.0.1:8080", "адрес панели управления (порт занят → подберётся свободный; :0 = выбор ОС)")
	socks := flag.String("socks", "127.0.0.1:1080", "адрес SOCKS5 (порт занят → подберётся свободный; :0 = выбор ОС)")
	dataDir := flag.String("data", "data", "каталог данных (servers.json)")
	cbr := flag.Duration("cbr", 40*time.Millisecond, "интервал CBR-паддинга (0 = выкл)")
	flavorName := flag.String("flavor", "auto", "маска ритма: auto, vk-video, rutube, kinopoisk, vk-feed, yandex, sber, gosuslugi, wb-ozon, mail, steam-dl, steam-app")
	tunMode := flag.Bool("tun", false, "TUN-режим: автоподхват всего TCP (нужен admin)")
	dnsAddr := flag.String("dns", "127.0.0.1:53", "адрес DNS-резолвера через туннель (на Android: 127.0.0.1:5353; порт занят → подберётся свободный)")
	sysProxy := flag.Bool("sysproxy", true, "без TUN: ставить системный прокси Windows автоматически")
	timeout := flag.Duration("timeout", 8*time.Second, "таймаут подключения к ноде")
	tunProbe := flag.Bool("tun-probe", false, "внутренний режим: проба создания адаптера Wintun")
	autoConn := flag.Bool("autoconnect", true, "автоматически подключаться к первой ноде при запуске")
	autopilotOn := flag.Bool("autopilot", true, "автопилот: профилирование сети и авто-обход (DoH-резолв нод, ротация flavor/decoy, чтение борда при обрывах)")
	exoOn := flag.Bool("exo", true, "слой 7: экзогенная сенсорика — пулл публичных измерений OONI (RU) в data/netprofile.jsonl")
	flag.Parse()

	if *tunProbe {
		RunTunProbe() // только проба адаптера; никогда не возвращается на Windows
		return
	}

	store, err := LoadStore(filepath.Join(*dataDir, "servers.json"))
	if err != nil {
		log.Fatal(err)
	}
	// Персональный ключ этого устройства (белый список на ноде).
	clientKey, clientPub, err := loadOrCreateClientKey(filepath.Join(*dataDir, "client.key"))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("chamd: ключ устройства (для белого списка ноды): %s", clientPub)
	suspLogger := NewSuspiciousLogger(*dataDir)
	m := NewManager(store, *timeout, *cbr, *flavorName, clientKey, suspLogger)

	cover := NewCover(m)
	ap := NewAutopilot(m, cover)
	ap.SetDataDir(*dataDir) // F1: netprofile.jsonl пишется в каталог данных
	ap.SetExo(*exoOn, "")   // слой 7: экзогенная сенсорика (OONI)
	if *tunMode {
		td := NewTun(m)
		td.SetSocks(*socks)
		// Легенда должна идти МИМО туннеля — иначе провайдер её не увидит,
		// а канал ноды будет расходоваться на мусор.
		cover.SetBypassAdder(td.AddCoverBypass)
		ap.SetBypassAdder(td.AddCoverBypass) // пробы автопилота — мимо туннеля
		go serveDNS(m, *dnsAddr)
		m.SetHooks(
			func() {
				if err := td.Start(); err != nil {
					m.logf("tun: %v — работаем через SOCKS5 %s", err, *socks)
				}
			},
			func() { td.Stop() },
		)
		// Ctrl+C / закрытие окна: вернуть маршруты и правило файрвола,
		// иначе интернет останется завёрнутым в мёртвый туннель.
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-sigCh
			// Stop() у tun2socks-движка может зависнуть — тогда процесс
			// остаётся зомби и держит порты 53/1080. Чистим в фоне,
			// а через 3 секунды выходим безусловно.
			done := make(chan struct{})
			go func() {
				td.Stop()
				SetSystemProxy(false, *socks)
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				log.Printf("chamd: принудительный выход (очистка заняла >3с)")
			}
			os.Exit(0)
		}()
		m.logf("режим: TUN (автоподхват всего TCP)")
	} else if *sysProxy {
		addr := *socks
		m.SetHooks(
			func() {
				if err := SetSystemProxy(true, addr); err != nil {
					m.logf("sysproxy: %v", err)
				} else {
					m.logf("системный прокси Windows → socks://%s (подхвачено автоматически)", addr)
				}
			},
			func() {
				if err := SetSystemProxy(false, addr); err != nil {
					m.logf("sysproxy off: %v", err)
				}
			},
		)
		m.logf("режим: системный прокси + SOCKS5 %s", *socks)
	}

	cover.Start()
	defer cover.Stop()

	// Автопилот: профиль → план → локальное исполнение (измеряет и обходит).
	m.SetOnSessionDrop(ap.OnSessionDrop)
	m.SetOnSessionUp(ap.OnSessionUp) // слой 3: выжившие канарейки
	if *autopilotOn {
		ap.Start() // первый профиль сразу: меряет сеть провайдера ДО поднятия TUN
		defer ap.Stop()
	}

	// Автоподключение: пользователь просто запускает chamd — дальше всё само.
	if *autoConn && len(store.List()) > 0 {
		go func() {
			time.Sleep(500 * time.Millisecond)
			if *autopilotOn {
				// Ждём первый профиль (меряет провайдера до поднятия TUN), кап 6 сек.
				select {
				case <-ap.FirstRunDone():
				case <-time.After(6 * time.Second):
				}
			}
			for attempt := 1; attempt <= 5; attempt++ {
				if err := m.Connect(0); err == nil {
					return
				}
				m.logf("автоподключение: попытка %d/5 не удалась, повтор через 3с", attempt)
				time.Sleep(3 * time.Second)
			}
		}()
	}

	m.logf("chamd запущен: панель http://%s, cbr=%v, flavor=%s", *ui, *cbr, *flavorName)

	go func() {
		if err := serveSOCKS(*socks, m); err != nil {
			log.Fatal(err)
		}
	}()
	log.Printf("chamd: панель http://%s", *ui)
	if err := serveUI(*ui, m); err != nil {
		log.Fatal(err)
	}
}
