package chameleon

// cf_reference.go — REAL reference data curated from public internet sources.
//
// These are real, public endpoints and popular domains used as cover traffic /
// decoy origins. They are reference data (not secrets): public DoH resolvers
// and widely-visited domains. Used by the Control Fabric to choose decoy
// origins and DoH endpoints at runtime.

// PublicDoHEndpoints are real public DNS-over-HTTPS resolvers.
var PublicDoHEndpoints = []string{
	"https://1.1.1.1/dns-query",         // Cloudflare
	"https://dns.google/resolve",        // Google
	"https://dns.mullvad.net/dns-query", // Mullvad
	"https://dns.quad9.net:5053/dns-query",
}

// PopularDecoys are real, widely-visited domains usable as decoy origins for
// cover TLS handshakes (abort-on-handshake / early-cut cover traffic).
var PopularDecoys = []string{
	"vk.com",
	"yandex.ru",
	"google.com",
	"youtube.com",
	"github.com",
	"cloudflare.com",
	"steamcommunity.com",
	"gosuslugi.ru",
}

// PickDoHEndpoint selects a public DoH resolver deterministically by index.
func PickDoHEndpoint(index int) string {
	if len(PublicDoHEndpoints) == 0 {
		return "https://1.1.1.1/dns-query"
	}
	return PublicDoHEndpoints[index%len(PublicDoHEndpoints)]
}

// PickDecoy selects a decoy origin deterministically by index.
func PickDecoy(index int) string {
	if len(PopularDecoys) == 0 {
		return "example.com"
	}
	return PopularDecoys[index%len(PopularDecoys)]
}
