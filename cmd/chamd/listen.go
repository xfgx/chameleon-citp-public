package main

// listen.go — кастомные порты слушателей (раунд 6).
//
// Раньше порты были жёстко заданы дефолтами (127.0.0.1:1080 SOCKS5,
// 127.0.0.1:8080 панель, 127.0.0.1:53 DNS): занятый порт = chamd не стартует.
// Теперь запрошенный адрес — предпочтение: занятый порт сканируется дальше
// (до +100), порт 0 отдаётся ОС. Фактический адрес уходит в журнал и в панель
// (Manager.SetListenAddr → Status.Listen). Флаги -socks/-ui/-dns работают как
// прежде.

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// listenTCP открывает TCP-слушатель на желаемом адресе; при занятом порте
// сканирует следующие (до +100). Возвращает слушатель и фактический адрес.
func listenTCP(m *Manager, addr, label string) (net.Listener, string, error) {
	ln, actual, err := listenTCPScanned(addr)
	if err != nil {
		return nil, "", err
	}
	if actual != addr {
		m.logf("порты: %s: %s занят, слушаю %s", label, addr, actual)
	}
	return ln, actual, nil
}

// listenUDP — то же для UDP-пакетного слушателя.
func listenUDP(m *Manager, addr, label string) (net.PacketConn, string, error) {
	pc, actual, err := listenUDPScanned(addr)
	if err != nil {
		return nil, "", err
	}
	if actual != addr {
		m.logf("порты: %s: %s занят, слушаю %s", label, addr, actual)
	}
	return pc, actual, nil
}

// listenTCPScanned — механика сканирования без журнала (тестируемо).
func listenTCPScanned(addr string) (net.Listener, string, error) {
	var lastErr error
	for _, candidate := range addrCandidates(addr) {
		ln, err := net.Listen("tcp", candidate)
		if err == nil {
			return ln, ln.Addr().String(), nil
		}
		if !isAddrInUse(err) {
			return nil, "", err
		}
		lastErr = err
	}
	return nil, "", fmt.Errorf("порты заняты (%s и следующие 100): %w", addr, lastErr)
}

// listenUDPScanned — UDP-вариант сканирования.
func listenUDPScanned(addr string) (net.PacketConn, string, error) {
	var lastErr error
	for _, candidate := range addrCandidates(addr) {
		pc, err := net.ListenPacket("udp", candidate)
		if err == nil {
			return pc, pc.LocalAddr().String(), nil
		}
		if !isAddrInUse(err) {
			return nil, "", err
		}
		lastErr = err
	}
	return nil, "", fmt.Errorf("порты заняты (%s и следующие 100): %w", addr, lastErr)
}

// addrCandidates — запрошенный адрес + до 100 следующих портов.
// Порт 0 (выбор ОС) возвращается как есть, без сканирования; невалидный
// адрес — одна попытка, ошибка всплывёт из net.Listen.
func addrCandidates(addr string) []string {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return []string{addr}
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port == 0 {
		return []string{addr}
	}
	out := make([]string, 0, 101)
	for p := port; p <= port+100 && p <= 65535; p++ {
		out = append(out, net.JoinHostPort(host, strconv.Itoa(p)))
	}
	return out
}

// isAddrInUse — cross-platform признак «порт занят» по тексту ошибки.
func isAddrInUse(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "address already in use") ||
		strings.Contains(s, "address is already in use") ||
		strings.Contains(s, "only one usage of each socket address") // Windows WSAEADDRINUSE
}
