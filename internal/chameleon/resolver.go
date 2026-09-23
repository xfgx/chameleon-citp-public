package chameleon

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// ResolutionObject — криптографически подтверждённый ответ ноды на RESOLVE.
// Привязан к сессии (подписан seed'ом), содержит expiry и защищает от DNS rebinding:
// клиент не может подменить IP, а нода при OPEN проверяет, что цель соответствует
// разрешённому домену.
type ResolutionObject struct {
	Domain string
	Addrs  []string // разрешённые IP-адреса
	Expiry int64    // unix seconds
	Sig    []byte   // HMAC-SHA256(seed, canonical v2 encoding)
}

const (
	ResolutionAuthVersion = 2
	resolveTTL            = 300 * time.Second // 5 минут по умолчанию
	maxResolvedAddresses  = 64                // максимальное количество IP-адресов в ResolutionObject
)

// Encode сериализует ResolutionObject в байты для передачи по туннелю.
func (r *ResolutionObject) Encode() []byte {
	if r == nil || len(r.Sig) != sha256.Size {
		return nil
	}
	b := r.unsignedData()
	if b == nil {
		return nil
	}
	return append(b, r.Sig...)
}

func (r *ResolutionObject) unsignedData() []byte {
	if r == nil || len(r.Domain) == 0 || len(r.Domain) > 253 || strings.TrimSpace(r.Domain) != r.Domain ||
		strings.ContainsAny(r.Domain, "\x00\r\n\t /\\") || len(r.Addrs) == 0 || len(r.Addrs) > maxResolvedAddresses || r.Expiry <= 0 {
		return nil
	}
	b := make([]byte, 0, 1+len(r.Domain)+1+len(r.Addrs)*17+8)
	b = append(b, byte(len(r.Domain)))
	b = append(b, r.Domain...)
	b = append(b, byte(len(r.Addrs)))
	for _, addr := range r.Addrs {
		if len(addr) > 255 || net.ParseIP(addr) == nil {
			return nil
		}
		b = append(b, byte(len(addr)))
		b = append(b, addr...)
	}
	return binary.BigEndian.AppendUint64(b, uint64(r.Expiry))
}

// DecodeResolutionObject разбирает сериализацию.
func DecodeResolutionObject(b []byte) (*ResolutionObject, error) {
	if len(b) < 1+8+32 {
		return nil, fmt.Errorf("resolution object too short")
	}
	r := &ResolutionObject{}
	off := 0
	dl := int(b[off])
	off++
	if len(b) < off+dl+1 {
		return nil, fmt.Errorf("resolution object truncated (domain)")
	}
	r.Domain = string(b[off : off+dl])
	if r.Domain == "" || len(r.Domain) > 253 || strings.TrimSpace(r.Domain) != r.Domain {
		return nil, fmt.Errorf("resolution object has invalid domain")
	}
	off += dl
	na := int(b[off])
	off++
	if na > maxResolvedAddresses {
		return nil, fmt.Errorf("resolution object exceeds maximum address limit (%d > %d)", na, maxResolvedAddresses)
	}
	// Проверяем, что в оставшемся буфере физически может поместиться как минимум na адресов (по 1 байту длины) + 8B expiry + 32B sig
	if len(b)-off < na+8+32 {
		return nil, fmt.Errorf("resolution object truncated for declared address count")
	}
	r.Addrs = make([]string, 0, na)
	for i := 0; i < na; i++ {
		if len(b) <= off {
			return nil, fmt.Errorf("resolution object truncated (addr %d)", i)
		}
		al := int(b[off])
		off++
		if len(b) < off+al {
			return nil, fmt.Errorf("resolution object truncated (addr %d data)", i)
		}
		addr := string(b[off : off+al])
		if net.ParseIP(addr) == nil {
			return nil, fmt.Errorf("resolution object has invalid addr %d", i)
		}
		r.Addrs = append(r.Addrs, addr)
		off += al
	}
	if len(b) < off+8+32 {
		return nil, fmt.Errorf("resolution object truncated (expiry/sig)")
	}
	r.Expiry = int64(binary.BigEndian.Uint64(b[off:]))
	off += 8
	r.Sig = append([]byte(nil), b[off:off+32]...)
	off += 32
	if off != len(b) {
		return nil, fmt.Errorf("resolution object has trailing data")
	}
	if r.unsignedData() == nil {
		return nil, fmt.Errorf("resolution object has invalid fields")
	}
	return r, nil
}

// Sign подписывает объект HMAC-SHA256 от seed сессии.
func (r *ResolutionObject) Sign(seed []byte) {
	if r == nil {
		return
	}
	data := r.signedData()
	if data == nil {
		r.Sig = nil
		return
	}
	r.Sig = hmacSHA256(seed, data)
}

// Verify проверяет подпись и срок действия объекта.
func (r *ResolutionObject) Verify(seed []byte) error {
	if r == nil || len(r.Sig) != sha256.Size || r.unsignedData() == nil {
		return fmt.Errorf("resolution object has invalid fields or signature length")
	}
	if time.Now().Unix() >= r.Expiry {
		return fmt.Errorf("resolution object expired")
	}
	want := hmacSHA256(seed, r.signedData())
	if !hmac.Equal(r.Sig, want) {
		return fmt.Errorf("resolution object signature mismatch")
	}
	return nil
}

// MatchAddr проверяет, что данный host:port разрешён этим ResolutionObject.
func (r *ResolutionObject) MatchAddr(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	return r.MatchHost(host)
}

// MatchHost проверяет, что host (IP или домен) покрыт этим объектом:
// либо это сам разрешённый домен, либо IP из подписанного набора.
func (r *ResolutionObject) MatchHost(host string) bool {
	if strings.EqualFold(strings.TrimSuffix(host, "."), r.Domain) {
		return true
	}
	for _, a := range r.Addrs {
		if a == host {
			return true
		}
	}
	return false
}

func (r *ResolutionObject) signedData() []byte {
	body := r.unsignedData()
	if body == nil {
		return nil
	}
	// v2 deliberately does not accept the ambiguous legacy concatenation.
	return append([]byte("citp-resolution-v2\x00"), body...)
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// AllowPrivateResolution разрешает ноде выдавать приватные/loopback-адреса
// в ResolutionObject. По умолчанию выключено (anti-SSRF/anti-rebinding:
// нода не должна ходить в чужие внутренние сети). true — только в тестах.
var AllowPrivateResolution = false

const maxResolveAddrs = 16

// ResolveDomain — серверная сторона: резолвит домен через системный DNS
// ноды (доверенный резолвер), отбрасывает непубличные адреса, создаёт
// ResolutionObject с TTL и подписывает его ключом сеанса.
func ResolveDomain(domain string, seed []byte) (*ResolutionObject, error) {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domain == "" || len(domain) > 253 || net.ParseIP(domain) != nil {
		return nil, fmt.Errorf("невалидный домен %q", domain)
	}
	ips, err := net.LookupHost(domain)
	if err != nil {
		return nil, err
	}
	r := &ResolutionObject{
		Domain: domain,
		Addrs:  make([]string, 0, len(ips)),
		Expiry: time.Now().Add(resolveTTL).Unix(),
	}
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if !AllowPrivateResolution && !isPublicResolutionIP(ip) {
			continue
		}
		r.Addrs = append(r.Addrs, ipStr)
		if len(r.Addrs) >= maxResolveAddrs {
			break
		}
	}
	if len(r.Addrs) == 0 {
		return nil, fmt.Errorf("нет публичных адресов для %s (private/loopback отфильтрованы)", domain)
	}
	r.Sign(seed)
	return r, nil
}

// isPublicResolutionIP — отсев private/loopback/link-local/multicast/CGNAT.
func isPublicResolutionIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() ||
		ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 0 || (ip4[0] == 100 && ip4[1]&0xC0 == 64) || ip4[0] >= 224 {
			return false
		}
	}
	return true
}
