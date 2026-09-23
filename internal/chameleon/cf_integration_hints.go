package chameleon

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net"
	"strings"
	"sync"
)

type ControlFabricNodeHint struct {
	NodeIP     string `json:"node_ip"`
	CDNBaseURL string `json:"cdn_base_url,omitempty"`
	CARBaseURL string `json:"car_base_url,omitempty"`
	DNSHost    string `json:"dns_host,omitempty"`
	DNSPort    string `json:"dns_port,omitempty"`
	PCIPMode   string `json:"pc_ip_mode"`
}

var controlHintState struct {
	sync.RWMutex
	hint ControlFabricNodeHint
}

func SetControlFabricNodeHint(nodeIP, cdnListen, carListen, dnsListen string) {
	controlHintState.Lock()
	defer controlHintState.Unlock()
	controlHintState.hint = ControlFabricNodeHint{
		NodeIP:   normalizeAdvertiseHost(nodeIP),
		PCIPMode: "auto-from-client-socket", // PC IP is learned from the client socket per session (ControlPeerIP)
	}
	if controlHintState.hint.NodeIP == "" {
		controlHintState.hint.NodeIP = normalizeAdvertiseHost(hostFromListen(cdnListen))
	}
	if controlHintState.hint.NodeIP == "" {
		// fully adaptive: discover the node address from this machine
		controlHintState.hint.NodeIP = normalizeAdvertiseHost(DetectNodeIP())
	}
	if cdnListen != "" {
		controlHintState.hint.CDNBaseURL = "https://" + net.JoinHostPort(controlHintState.hint.NodeIP, portFromListen(cdnListen))
	}
	if carListen != "" {
		controlHintState.hint.CARBaseURL = "http://" + net.JoinHostPort(controlHintState.hint.NodeIP, portFromListen(carListen))
	}
	if dnsListen != "" {
		controlHintState.hint.DNSHost = controlHintState.hint.NodeIP
		controlHintState.hint.DNSPort = portFromListen(dnsListen)
	}
}

func ControlBootstrapHint() []byte {
	controlHintState.RLock()
	h := controlHintState.hint
	controlHintState.RUnlock()
	b, _ := json.Marshal(h)
	return b
}

// SetControlFabricBoardURL overrides the bulletin URL advertised to clients:
// with an external board (CDN worker / object storage), clients poll the board
// instead of the node itself, so the control channel survives a full IP block
// of the node.
func SetControlFabricBoardURL(boardURL string) {
	controlHintState.Lock()
	defer controlHintState.Unlock()
	controlHintState.hint.CDNBaseURL = boardURL
}

func ControlSessionID(clientPub []byte) string {
	sum := sha256.Sum256(clientPub)
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

func normalizeAdvertiseHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" || host == "localhost" || host == "127.0.0.1" {
		return ""
	}
	return strings.Trim(host, "[]")
}

func hostFromListen(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return host
}

func portFromListen(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return port
}

// ControlSessionIDFor — идентификатор broadcast-канала борда (слои 6/8):
// производный от публичного ключа клиента sid, не пересекающийся с
// hint-каналом (ControlSessionID) за счёт доменного разделителя. Тот же
// 22-символьный base64url-формат — проходит валидацию sid на воркере.
func ControlSessionIDFor(clientPub []byte, channel string) string {
	h := sha256.New()
	h.Write([]byte("cf-channel:"))
	h.Write([]byte(channel))
	h.Write([]byte{0})
	h.Write(clientPub)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:16])
}
