package chameleon

import (
	"net"
	"time"
)

// ServeMuxWithCST — серверная сторона мультиплексора с включённым слоем CST
// (Continuity Stream Transport): помимо legacy open/resolve обрабатывает
// CST-кадры через реестр потоков cstCfg.Registry.
func ServeMuxWithCST(conn *Conn, dialTimeout time.Duration, policy *PolicyEngine,
	onCITP func(m *Mux, obj *CITPObject),
	egress, egressUDP func(hostport string) (net.Conn, error),
	resolveDisabled bool, cstCfg *CSTServerConfig) {
	if policy == nil {
		policy = NewPolicyEngine(DefaultPolicy())
	}
	serveMuxWithConfig(conn, dialTimeout, policy, onCITP, egress, egressUDP, resolveDisabled, cstCfg)
}
