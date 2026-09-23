package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// SuspiciousEvent — запись о подозрительной или аномальной сетевой активности.
type SuspiciousEvent struct {
	Timestamp   string `json:"timestamp"`
	Category    string `json:"category"` // SSRF_PROBE, PORT_SCAN, DNS_REBIND, DESYNC, AUTH_ANOMALY, TRAFFIC_SPIKE
	Severity    string `json:"severity"` // LOW, MEDIUM, HIGH, CRITICAL
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Description string `json:"description"`
}

// SuspiciousLogger ведет журнал и аудит аномалий, сохраняя их на диск (data/suspicious.json).
type SuspiciousLogger struct {
	mu       sync.RWMutex
	filePath string
	events   []SuspiciousEvent
}

func NewSuspiciousLogger(dataDir string) *SuspiciousLogger {
	sl := &SuspiciousLogger{
		filePath: filepath.Join(dataDir, "suspicious.json"),
		events:   make([]SuspiciousEvent, 0),
	}
	sl.load()
	return sl
}

func (sl *SuspiciousLogger) load() {
	b, err := os.ReadFile(sl.filePath)
	if err == nil {
		var list []SuspiciousEvent
		if err := json.Unmarshal(b, &list); err == nil {
			sl.events = list
		}
	}
}

func (sl *SuspiciousLogger) saveLocked() {
	if err := os.MkdirAll(filepath.Dir(sl.filePath), 0o755); err != nil {
		return
	}
	// Ограничиваем историю последними 500 событиями
	if len(sl.events) > 500 {
		sl.events = sl.events[len(sl.events)-500:]
	}
	b, err := json.MarshalIndent(sl.events, "", "  ")
	if err == nil {
		_ = os.WriteFile(sl.filePath, b, 0o600)
	}
}

// LogAnomaly добавляет подозрительное событие в память и сохраняет на диск.
func (sl *SuspiciousLogger) LogAnomaly(category, severity, src, dst, desc string) {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	ev := SuspiciousEvent{
		Timestamp:   time.Now().Format("2006-01-02 15:04:05"),
		Category:    category,
		Severity:    severity,
		Source:      src,
		Destination: dst,
		Description: desc,
	}
	sl.events = append(sl.events, ev)
	sl.saveLocked()
}

// Events возвращает копию списка зарегистрированных событий.
func (sl *SuspiciousLogger) Events() []SuspiciousEvent {
	sl.mu.RLock()
	defer sl.mu.RUnlock()
	res := make([]SuspiciousEvent, len(sl.events))
	copy(res, sl.events)
	return res
}

// Clear очищает журнал подозрительных событий.
func (sl *SuspiciousLogger) Clear() {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	sl.events = make([]SuspiciousEvent, 0)
	sl.saveLocked()
}

// InspectTarget анализирует попытку соединения на признаки SSRF, обращения к локальным IP, приватным сетям и подозрительным портам.
func (sl *SuspiciousLogger) InspectTarget(target, clientAddr string) bool {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}
	host = strings.Trim(host, "[]")

	// 1. Проверка на приватные/петлевые адреса (Anti-SSRF / Internal Scan)
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() {
			sl.LogAnomaly("SSRF_PROBE", "HIGH", clientAddr, target, "Попытка обращения к Loopback интерфейсу ("+ip.String()+")")
			return true
		}
		if ip.IsPrivate() {
			sl.LogAnomaly("INTERNAL_PROBE", "MEDIUM", clientAddr, target, "Попытка подключения к приватной подсети RFC1918 ("+ip.String()+")")
			return true
		}
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			sl.LogAnomaly("SSRF_PROBE", "HIGH", clientAddr, target, "Попытка обращения к Link-Local адресу ("+ip.String()+")")
			return true
		}
	}

	// 2. Проверка на подозрительные порты (SMB, NetBIOS, Telnet, SSH brute-scan и др.)
	if portStr != "" {
		if p, err := net.LookupPort("tcp", portStr); err == nil {
			switch p {
			case 23:
				sl.LogAnomaly("PORT_SCAN", "MEDIUM", clientAddr, target, "Подозрительное подключение к Telnet (Port 23)")
				return true
			case 445, 135, 137, 138, 139:
				sl.LogAnomaly("PORT_SCAN", "HIGH", clientAddr, target, fmt.Sprintf("Попытка доступа к портам SMB/RPC (%d)", p))
				return true
			case 3389:
				sl.LogAnomaly("SUSPICIOUS_PORT", "LOW", clientAddr, target, "Подключение к RDP сервису (Port 3389)")
			}
		}
	}

	// 3. Проверка на локальные имена
	lowerHost := strings.ToLower(host)
	if lowerHost == "localhost" || strings.HasSuffix(lowerHost, ".local") || strings.HasSuffix(lowerHost, ".internal") {
		sl.LogAnomaly("SSRF_PROBE", "HIGH", clientAddr, target, "Попытка резолва/обращения к внутреннему домену ("+host+")")
		return true
	}

	return false
}
