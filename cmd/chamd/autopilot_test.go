package main

import (
	"testing"
	"time"

	"chameleon/internal/chameleon"
)

func testManager(t *testing.T) *Manager {
	t.Helper()
	store, err := LoadStore(t.TempDir() + "/servers.json")
	if err != nil {
		t.Fatal(err)
	}
	return NewManager(store, 2*time.Second, 0, "auto", "", nil)
}

// Подтверждённый перехват DNS -> автопилот включает DoH-режим и реконнект.
func TestAutopilotAppliesDoHOnHijack(t *testing.T) {
	m := testManager(t)
	ap := NewAutopilot(m, NewCover(m))
	prof := chameleon.CensorProfile{
		HasDPI: true, DNSLikelyHijack: true,
		ResolverPlain: "203.0.113.9", ResolverDoH: "172.68.9.76",
	}
	plan := chameleon.NewAdaptiveCarrierSelector(chameleon.DefaultCarrierProfiles()).Select(prof)
	ap.applyPlan(prof, plan)
	if !m.DoHMode() {
		t.Fatal("DoH-режим должен включиться по dns_likely_hijack")
	}
	// Повтор идемпотентен: не паникует, режим остаётся.
	ap.applyPlan(prof, plan)
	if !m.DoHMode() {
		t.Fatal("DoH-режим должен остаться включённым")
	}
}

// Чистая сеть (actions: []) -> ничего не переключается.
func TestAutopilotCleanPlanNoop(t *testing.T) {
	m := testManager(t)
	ap := NewAutopilot(m, NewCover(m))
	plan := chameleon.NewAdaptiveCarrierSelector(chameleon.DefaultCarrierProfiles()).Select(chameleon.CensorProfile{})
	if len(plan.Actions) != 0 {
		t.Fatalf("чистая сеть должна давать пустой план, получено %d действий", len(plan.Actions))
	}
	ap.applyPlan(chameleon.CensorProfile{}, plan)
	if m.DoHMode() {
		t.Fatal("DoH-режим не должен включаться в чистой сети")
	}
}

// Шумный dns_poisoning без подтверждённого перехвата -> DoH НЕ включается.
func TestAutopilotIgnoresAnycastNoise(t *testing.T) {
	m := testManager(t)
	ap := NewAutopilot(m, NewCover(m))
	prof := chameleon.CensorProfile{HasDPI: true, DNSPoisoning: true, DNSLikelyHijack: false}
	plan := chameleon.NewAdaptiveCarrierSelector(chameleon.DefaultCarrierProfiles()).Select(prof)
	ap.applyPlan(prof, plan)
	if m.DoHMode() {
		t.Fatal("anycast-шум не должен включать DoH-режим")
	}
}

// dialAddr без DoH-режима — passthrough и для домена, и для IP.
func TestManagerDialAddrPassthroughWhenDoHOff(t *testing.T) {
	m := testManager(t)
	if got := m.dialAddr("example.com:8443"); got != "example.com:8443" {
		t.Fatalf("dialAddr изменил адрес при выкл. DoH: %s", got)
	}
	if got := m.dialAddr("1.2.3.4:8443"); got != "1.2.3.4:8443" {
		t.Fatalf("dialAddr изменил IP-адрес: %s", got)
	}
}

// Ротация flavor меняет значение.
func TestManagerRotateFlavorChanges(t *testing.T) {
	m := testManager(t)
	if a, b := m.RotateFlavor(), m.RotateFlavor(); a == b {
		t.Fatal("ротация flavor должна менять значение")
	}
}
