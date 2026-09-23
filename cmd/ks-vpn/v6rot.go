package main

// v6rot.go — ротация исходного IPv6-адреса клиента из СОБСТВЕННОГО
// делегированного префикса (routed /48 нашего 6in4-туннеля).
//
// Зачем: блокировка одного выходного IP теряет смысл — каждые N секунд
// (флаг -v6rot) на TUN-адаптер добавляется новый случайный адрес пула,
// прежние помечаются «не выбирать для новых потоков» (Windows SkipAsSource /
// Linux preferred_lft=0). Новые соединения и однопакетные запросы
// (DNS/UDP/ICMPv6) уходят немедленно с нового адреса; живые TCP-сессии
// доживают на своём (стек привязывает источник к потоку — это требование
// протокола, а не ограничение ротации).
//
// Нода ничего не знает об адресах: RU и выход маршрутизируют весь /48
// префиксно — «подхватывание» автоматическое, без поадресной настройки.
// Доступные адреса — только наши (anti-spoof гард на нодах отбрасывает из
// туннеля источники вне пула).
//
// Отказоустойчивость: любая ошибка применения адреса — честный отказ/лог,
// туннель v4 продолжает работать (v6 — аддитивная функция).

import (
	"bytes"
	"crypto/rand"
	"errors"
	"log"
	"net"
	"sync/atomic"
	"time"
)

// v6KeepAddrs — сколько прошлых адресов держим на адаптере: их потоки ещё
// живы и принимают ответы (обратный маршрут — префиксный, приём работает).
// Сверх окна адреса удаляются, чтобы адаптер не обрастал тысячами записей.
const v6KeepAddrs = 32

// v6cur — текущий предпочтительный адрес (для строки стадий).
var v6cur atomic.Value // string

// Ошибки генератора (честные, без имитаций).
var (
	errV6BadPrefix = errors.New("v6rot: префикс не IPv6")
	errV6TooNarrow = errors.New("v6rot: префикс /128 — ротировать нечего")
	errV6NoDraw    = errors.New("v6rot: не удалось вытянуть допустимый адрес за 100 попыток")
)

// v6AddrMgr — платформенный применятор адресов пула (windows/linux).
type v6AddrMgr interface {
	// Setup — подготовка адаптера/маршрутов; возвращает функцию отката.
	Setup() (func(), error)
	// Add — добавить адрес /128 и сделать его предпочтительным источником
	// (прежние адреса пула демотируются, но продолжают принимать ответы).
	Add(ip net.IP) error
	// Prune — оставить не более keep последних адресов пула.
	Prune(keep int) error
}

// v6Rotator — периодический генератор+применятор адресов пула.
type v6Rotator struct {
	prefix *net.IPNet
	ones   int
	mgr    v6AddrMgr
	period time.Duration
	stop   chan struct{}
}

// newV6Rotator — разбор флагов; periodSec<1 зажимается до 1 (защита от
// опечатки: слишком частая смена только плодит мёртвые адреса).
func newV6Rotator(prefixCIDR, ifname string, periodSec uint64) (*v6Rotator, error) {
	ip, ipnet, err := net.ParseCIDR(prefixCIDR)
	if err != nil {
		return nil, err
	}
	if ip.To4() != nil || ipnet.IP.To16() == nil {
		return nil, errV6BadPrefix
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 128 {
		return nil, errV6BadPrefix
	}
	if ones >= 128 {
		return nil, errV6TooNarrow
	}
	if periodSec < 1 {
		periodSec = 1
	}
	return &v6Rotator{
		prefix: ipnet, ones: ones, mgr: newV6AddrMgr(ifname),
		period: time.Duration(periodSec) * time.Second, stop: make(chan struct{}),
	}, nil
}

// randV6 — случайный адрес из префикса (crypto/rand по хостовым битам).
// Исключения (deterministic, задокументированы):
//   - адрес == адресу сети (subnet-router anycast) — перегенерация;
//   - нижний /64 префикса (при длине < /64): там живут адреса самих узлов
//     6in4 (::1 брокер, ::2 наш конец) — коллизия маршрутов на выходе.
func randV6(prefix *net.IPNet) (net.IP, error) {
	base := prefix.IP.To16()
	ones, bits := prefix.Mask.Size()
	if base == nil || bits != 128 {
		return nil, errV6BadPrefix
	}
	if ones >= 128 {
		return nil, errV6TooNarrow
	}
	var rb [16]byte
	for attempt := 0; attempt < 100; attempt++ {
		if _, err := rand.Read(rb[:]); err != nil {
			return nil, err
		}
		out := make(net.IP, 16)
		for i := 0; i < 16; i++ {
			var m byte
			switch {
			case 8*i+8 <= ones:
				m = 0xff
			case 8*i >= ones:
				m = 0x00
			default:
				m = 0xff << uint(8-(ones-8*i))
			}
			out[i] = (base[i] & m) | (rb[i] &^ m)
		}
		if bytes.Equal(out, base) {
			continue // subnet-router anycast
		}
		if ones < 64 && bytes.Equal(out[:8], base[:8]) {
			continue // нижний /64 — адреса узлов туннеля
		}
		return out, nil
	}
	return nil, errV6NoDraw
}

// Start — подготовка (маршрут ::/0 на Windows), первый адрес сразу, далее
// тикер. Возвращает откат (остановка + зачистка).
func (r *v6Rotator) Start() (func(), error) {
	cleanup, err := r.mgr.Setup()
	if err != nil {
		return nil, err
	}
	if err := r.rotate(); err != nil {
		cleanup()
		return nil, err
	}
	go func() {
		tk := time.NewTicker(r.period)
		defer tk.Stop()
		for {
			select {
			case <-r.stop:
				return
			case <-tk.C:
				if err := r.rotate(); err != nil {
					log.Printf("v6rot: %v (следующая попытка по тикеру)", err)
				}
			}
		}
	}()
	log.Printf("v6rot: пул %s, смена адреса каждые %s", r.prefix, r.period)
	return func() {
		close(r.stop)
		cleanup()
	}, nil
}

// rotate — одна смена адреса.
func (r *v6Rotator) rotate() error {
	ip, err := randV6(r.prefix)
	if err != nil {
		return err
	}
	if err := r.mgr.Add(ip); err != nil {
		return err
	}
	r.mgr.Prune(v6KeepAddrs)
	v6cur.Store(ip.String())
	log.Printf("v6rot: исходный -> %s", ip)
	return nil
}

// v6WirePinner — платформенная возможность запинить пул v6-ПРОВОДА ноды
// мимо туннельного ::/0 (иначе датаграммы провода к пулу ноды уйдут в наш же
// TUN — петля). Реально нужен Windows (клиент с -v6prefix); Linux — no-op
// (маршруты ставит обвязка стенда/хоста).
type v6WirePinner interface {
	PinWirePool(prefix *net.IPNet) error
}

// PinWirePool — делегат на платформенный менеджер, если он это умеет.
func (r *v6Rotator) PinWirePool(prefix *net.IPNet) error {
	p, ok := r.mgr.(v6WirePinner)
	if !ok {
		return nil // платформа не умеет — решает вызывающий
	}
	if err := p.PinWirePool(prefix); err != nil {
		log.Printf("v6rot: пул провода %s НЕ уведён мимо туннеля: %v", prefix, err)
		return err
	}
	return nil
}

// v6curStr — текущий адрес для строки стадий ("-" пока не было ротаций).
func v6curStr() string {
	if v := v6cur.Load(); v != nil {
		return v.(string)
	}
	return "-"
}
