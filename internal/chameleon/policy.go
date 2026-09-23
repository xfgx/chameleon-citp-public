package chameleon

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PolicyDecision результат вычисления политики.
type PolicyDecision string

const (
	PolicyAllow         PolicyDecision = "ALLOW"
	PolicyDeny          PolicyDecision = "DENY"
	PolicyRequireReauth PolicyDecision = "REQUIRE_REAUTH"
	PolicyRateLimited   PolicyDecision = "RATE_LIMITED"
)

// DeclarativePolicy — строго ограниченный декларативный bundle политик безопасности.
type DeclarativePolicy struct {
	Version            int      `json:"version"`
	TenantID           string   `json:"tenant_id"`
	ServiceID          string   `json:"service_id"`
	AllowedPorts       []int    `json:"allowed_ports"`       // пустой = все порты разрешены
	DenyPrivateRanges  bool     `json:"deny_private_ranges"` // Anti-SSRF
	DenyLinkLocal      bool     `json:"deny_link_local"`
	DenyLoopback       bool     `json:"deny_loopback"`
	AllowedDomains     []string `json:"allowed_domains"` // белый список доменов
	DeniedDomains      []string `json:"denied_domains"`  // черный список доменов
	MaxStreamsPerConn  int      `json:"max_streams_per_conn"`
	MaxStreamLifetimeS int      `json:"max_stream_lifetime_s"`
	RequireDNSBinding  bool     `json:"require_dns_binding"`
}

// DefaultPolicy возвращает безопасный профиль по умолчанию.
func DefaultPolicy() DeclarativePolicy {
	return DeclarativePolicy{
		Version:            1,
		TenantID:           "default",
		ServiceID:          "citp-core",
		AllowedPorts:       nil, // любые внешние
		DenyPrivateRanges:  true,
		DenyLinkLocal:      true,
		DenyLoopback:       true,
		MaxStreamsPerConn:  256,
		MaxStreamLifetimeS: 86400,
		RequireDNSBinding:  true,
	}
}

// PolicyEngine исполняет декларативные проверки перед открытием и при резолве.
type PolicyEngine struct {
	mu     sync.RWMutex
	policy DeclarativePolicy
}

func NewPolicyEngine(p DeclarativePolicy) *PolicyEngine {
	return &PolicyEngine{policy: p}
}

// EvaluateOpen проверяет возможность открытия потока к каноническому host:port.
func (pe *PolicyEngine) EvaluateOpen(hostport string) (PolicyDecision, string) {
	return pe.evaluateOpen(hostport, false)
}

// EvaluateOpenAllowingUnresolvedDomain — как EvaluateOpen, но без требования
// подписанного ResolutionObject для доменов: в режиме каскада нода→нода
// (chain) домен нарочно не резолвится входной нодой — DNS-binding и полную
// политику применяет выходная нода. Остальные правила (порты, списки доменов,
// приватные диапазоны) действуют полностью.
func (pe *PolicyEngine) EvaluateOpenAllowingUnresolvedDomain(hostport string) (PolicyDecision, string) {
	return pe.evaluateOpen(hostport, true)
}

func (pe *PolicyEngine) evaluateOpen(hostport string, allowUnresolvedDomain bool) (PolicyDecision, string) {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return PolicyDeny, "цель должна иметь формат host:port"
	}
	host = strings.ToLower(strings.TrimSuffix(strings.Trim(strings.TrimSpace(host), "[]"), "."))
	if host == "" {
		return PolicyDeny, "пустой host"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return PolicyDeny, "невалидный порт"
	}
	if len(pe.policy.AllowedPorts) > 0 {
		allowed := false
		for _, ap := range pe.policy.AllowedPorts {
			if ap == port {
				allowed = true
				break
			}
		}
		if !allowed {
			return PolicyDeny, fmt.Sprintf("порт %d запрещен политикой", port)
		}
	}

	if ip := net.ParseIP(host); ip != nil {
		if ip.IsUnspecified() || ip.IsMulticast() {
			return PolicyDeny, "unspecified/multicast адрес запрещен"
		}
		if pe.policy.DenyLoopback && ip.IsLoopback() {
			return PolicyDeny, "доступ к loopback адресам запрещен"
		}
		if pe.policy.DenyPrivateRanges && (ip.IsPrivate() || isCGNAT(ip)) {
			return PolicyDeny, "доступ к приватным сетям/CGNAT запрещен"
		}
		if pe.policy.DenyLinkLocal && (ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()) {
			return PolicyDeny, "доступ к link-local адресам запрещен"
		}
	} else {
		if pe.policy.RequireDNSBinding && !allowUnresolvedDomain {
			return PolicyDeny, "домен требует подписанный ResolutionObject"
		}
		if decision, reason := evaluateDomainLocked(pe.policy, host); decision != PolicyAllow {
			return decision, reason
		}
	}
	return PolicyAllow, ""
}

// EvaluateResolve applies the same domain allow/deny lists before DNS lookup.
func (pe *PolicyEngine) EvaluateResolve(domain string) (PolicyDecision, string) {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domain == "" || len(domain) > 253 || net.ParseIP(domain) != nil {
		return PolicyDeny, "невалидный домен"
	}
	return evaluateDomainLocked(pe.policy, domain)
}

func evaluateDomainLocked(p DeclarativePolicy, host string) (PolicyDecision, string) {
	for _, denied := range p.DeniedDomains {
		if domainMatches(host, denied) {
			return PolicyDeny, fmt.Sprintf("домен %s в черном списке", host)
		}
	}
	if len(p.AllowedDomains) > 0 {
		for _, allowed := range p.AllowedDomains {
			if domainMatches(host, allowed) {
				return PolicyAllow, ""
			}
		}
		return PolicyDeny, fmt.Sprintf("домен %s отсутствует в белом списке", host)
	}
	return PolicyAllow, ""
}

func domainMatches(host, suffix string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	suffix = strings.ToLower(strings.Trim(strings.TrimSpace(suffix), "."))
	return suffix != "" && (host == suffix || strings.HasSuffix(host, "."+suffix))
}

func isCGNAT(ip net.IP) bool {
	v4 := ip.To4()
	return v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 64
}

// MaxStreams returns a bounded per-session stream limit.
func (pe *PolicyEngine) MaxStreams() int {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	if pe.policy.MaxStreamsPerConn <= 0 || pe.policy.MaxStreamsPerConn > 4096 {
		return 256
	}
	return pe.policy.MaxStreamsPerConn
}

func (pe *PolicyEngine) MaxStreamLifetime() time.Duration {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	seconds := pe.policy.MaxStreamLifetimeS
	if seconds <= 0 || seconds > 7*24*60*60 {
		seconds = 24 * 60 * 60
	}
	return time.Duration(seconds) * time.Second
}

// SignedNodeDirectory — федеративный каталог нод с цифровой подписью провайдера.
type NodeDescriptor struct {
	NodeID       string   `json:"node_id"`
	Address      string   `json:"address"`
	PubKey       string   `json:"pubkey"`
	Capabilities []string `json:"capabilities"`
	Weight       int      `json:"weight"`
	Region       string   `json:"region"`
}

type SignedNodeDirectory struct {
	TenantID         string           `json:"tenant_id"`
	ServiceID        string           `json:"service_id"`
	DirectoryVersion uint64           `json:"directory_version"`
	ExpiresAt        int64            `json:"expires_at"` // unix timestamp
	Nodes            []NodeDescriptor `json:"nodes"`
	Signature        string           `json:"signature"`
}

// Sign подписывает директорию мастер-ключом провайдера.
func (d *SignedNodeDirectory) Sign(providerKey []byte) {
	data := d.signBytes()
	mac := hmac.New(sha256.New, providerKey)
	mac.Write(data)
	d.Signature = fmt.Sprintf("%x", mac.Sum(nil))
}

// Verify проверяет валидность и срок действия каталога нод.
func (d *SignedNodeDirectory) Verify(providerKey []byte, now int64) error {
	if d.ExpiresAt > 0 && now > d.ExpiresAt {
		return errors.New("node directory expired")
	}
	data := d.signBytes()
	mac := hmac.New(sha256.New, providerKey)
	mac.Write(data)
	expected := fmt.Sprintf("%x", mac.Sum(nil))
	if !hmac.Equal([]byte(d.Signature), []byte(expected)) {
		return errors.New("node directory signature mismatch")
	}
	return nil
}

func (d *SignedNodeDirectory) signBytes() []byte {
	// Детерминированный JSON для подписи
	clone := *d
	clone.Signature = ""
	b, _ := json.Marshal(clone)
	return b
}
