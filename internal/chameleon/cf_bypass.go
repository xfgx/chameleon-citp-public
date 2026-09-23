package chameleon

// cf_bypass.go — LOCAL adaptive carrier selector (auto-bypass planner).
//
// This is a LOCAL decision/planning layer, NOT a packet-level evasion engine.
// Given a CensorProfile (from cf_profiler.go), it selects which CITP carrier
// strategy to switch to. Every action that is local/simulated is marked with
// mode:"local". Actions that need real infrastructure remain
// ErrRequiresInfrastructure (refraction station, BGP write, foreign CDN).
//
// It does NOT implement: Geneva-style fragmentation/strategies, SNI spoofing,
// packet morphing, raw packet crafting, or any packet-level censorship-evasion
// primitive. It only maps "what the censor does" -> "which carrier to use".

import "encoding/json"

// BypassAction is one step in a BypassPlan. Mode is "local" for actions the
// client can perform locally, "infrastructure" for actions needing real infra.
type BypassAction struct {
	Trigger     string `json:"trigger"`  // what was detected
	Strategy    string `json:"strategy"` // recommended carrier/transport strategy
	Mode        string `json:"mode"`     // "local" or "infrastructure"
	Description string `json:"description"`
	// Local marks that this action is executed/simulated locally (local data,
	// local decision). Present and true for every local action.
	Local bool `json:"local"`
}

// BypassPlan is the output of the adaptive selector.
type BypassPlan struct {
	ProfileSummary string         `json:"profile_summary"` // LOCAL DATA: derived from the profile
	HasDPI         bool           `json:"has_dpi"`
	Actions        []BypassAction `json:"actions"`
	// LocalPlan is true if the plan is fully executable locally without extra
	// infrastructure (i.e. no action requires "infrastructure" mode).
	LocalPlan bool   `json:"local_plan"`
	Note      string `json:"note"` // LOCAL DATA: human-readable caveat
}

// AvailableCarrierProfiles is the local set of CITP carrier profiles the
// selector can recommend. LOCAL DATA: configured by the operator.
type AvailableCarrierProfiles struct {
	// DoHResolverCarrier: a carrier that resolves via DoH (bypasses plain-DNS poisoning).
	DoHResolverCarrier string
	// AlternateEntries: other entry nodes / carrier profiles to rotate to.
	AlternateEntries []string
	// RefractionCarrier: the on-path refraction carrier (needs infrastructure).
	RefractionCarrier string
	// Decoys: local decoy origin pool for cover traffic.
	Decoys []string
}

// DefaultCarrierProfiles returns a LOCAL default profile set.
// LOCAL DATA: these are placeholder carrier names; wire to real CITP carrier
// config in the production tree.
func DefaultCarrierProfiles() AvailableCarrierProfiles {
	return AvailableCarrierProfiles{
		DoHResolverCarrier: "citp-carrier-doh",
		AlternateEntries:   []string{"citp-carrier-quic", "citp-carrier-tcp-mux"},
		RefractionCarrier:  "refraction-tls",
		Decoys:             PopularDecoys,
	}
}

// AdaptiveCarrierSelector maps a CensorProfile to a BypassPlan.
type AdaptiveCarrierSelector struct {
	profiles AvailableCarrierProfiles
}

// NewAdaptiveCarrierSelector constructs a selector with the given (local) profiles.
func NewAdaptiveCarrierSelector(profiles AvailableCarrierProfiles) *AdaptiveCarrierSelector {
	if profiles.DoHResolverCarrier == "" {
		profiles = DefaultCarrierProfiles()
	}
	return &AdaptiveCarrierSelector{profiles: profiles}
}

// Select builds a BypassPlan from the profile. LOCAL DATA: the plan is derived
// locally from the profile; no network action is taken here.
func (s *AdaptiveCarrierSelector) Select(p CensorProfile) BypassPlan {
	plan := BypassPlan{
		ProfileSummary: ProfilerJSON(p), // LOCAL DATA
		HasDPI:         p.HasDPI,
		Note:           "local plan: selects carrier strategy only; no packet-level evasion", // LOCAL DATA
	}

	// Reliable DNS hijack -> switch resolver path to DoH (local, real action).
	// The raw DNSPoisoning flag is noisy (anycast/dual-stack variance) and must
	// NOT trigger a carrier switch by itself.
	if p.DNSLikelyHijack {
		plan.Actions = append(plan.Actions, BypassAction{
			Trigger:     "dns_likely_hijack",
			Strategy:    s.profiles.DoHResolverCarrier,
			Mode:        "local",
			Description: "switch resolver path to DoH (encrypted DNS), bypassing plain-DNS tampering",
			Local:       true,
		})
	}

	// HTTP block page -> rotate local endpoint/decoy choice (local).
	if p.HTTPBlockPage {
		decoy := ""
		if len(s.profiles.Decoys) > 0 {
			decoy = s.profiles.Decoys[0]
		}
		plan.Actions = append(plan.Actions, BypassAction{
			Trigger:     "http_block_page",
			Strategy:    "rotate-decoy",
			Mode:        "local",
			Description: "rotate local endpoint/decoy origin: " + decoy,
			Local:       true,
		})
	}

	// TCP RST / TLS(SNI) interference -> recommend an alternate CITP carrier
	// profile from local config (local). If SNI blocking is severe, the only
	// fully-SNI-hidden carrier is refraction, which needs infrastructure.
	if p.TCPResetInjection || p.TLSInterference {
		alt := ""
		if len(s.profiles.AlternateEntries) > 0 {
			alt = s.profiles.AlternateEntries[0]
		}
		plan.Actions = append(plan.Actions, BypassAction{
			Trigger:     "tcp_reset_or_sni_interference",
			Strategy:    alt,
			Mode:        "local",
			Description: "rotate to alternate CITP carrier profile from local config",
			Local:       true,
		})
		// The refraction carrier (no exposed SNI) is the robust answer for SNI
		// blocking but needs an on-path station — infrastructure-gated.
		if p.TLSInterference {
			plan.Actions = append(plan.Actions, BypassAction{
				Trigger:     "sni_interference_severe",
				Strategy:    s.profiles.RefractionCarrier,
				Mode:        "infrastructure",
				Description: "refraction carrier hides SNI but requires a cooperative on-path station (ErrRequiresInfrastructure)",
				Local:       false,
			})
		}
	}

	// Clean network => no actions at all (actions: []): nothing to switch.

	// Determine whether the whole plan is local (no infrastructure action).
	plan.LocalPlan = true
	for _, a := range plan.Actions {
		if a.Mode == "infrastructure" {
			plan.LocalPlan = false
			break
		}
	}
	return plan
}

// BypassPlanJSON renders the plan as indented JSON.
func BypassPlanJSON(plan BypassPlan) string {
	b, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return `{"error":"marshal failed"}`
	}
	return string(b)
}
