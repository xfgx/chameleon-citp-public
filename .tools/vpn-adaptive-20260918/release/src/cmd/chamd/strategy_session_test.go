package main

import (
	"sync/atomic"
	"testing"
	"time"

	"chameleon/internal/chameleon"
)

type observedSessionFixture struct {
	alive          atomic.Bool
	sent, received atomic.Uint64
}

func (s *observedSessionFixture) Alive() bool { return s.alive.Load() }
func (s *observedSessionFixture) PayloadStats() (uint64, uint64) {
	return s.sent.Load(), s.received.Load()
}

func TestStrategySessionOutcomes(t *testing.T) {
	for _, scenario := range []string{"survived", "idle", "dropped", "censored"} {
		t.Run(scenario, func(t *testing.T) {
			session := &observedSessionFixture{}
			session.alive.Store(scenario != "dropped")
			if scenario != "idle" {
				session.sent.Store(100)
				session.received.Store(200)
			}
			results := make(chan chameleon.StrategyOutcome, 2)
			cancel := observeStrategySession(session, 30*time.Millisecond, 2*time.Millisecond, func(outcome chameleon.StrategyOutcome) { results <- outcome })
			if scenario == "censored" {
				cancel()
				cancel()
				session.alive.Store(false)
			}
			select {
			case result := <-results:
				if result.Reason != scenario {
					t.Fatalf("got %+v, wanted %s", result, scenario)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("session monitor did not finish")
			}
			cancel()
			select {
			case result := <-results:
				t.Fatalf("duplicate outcome: %+v", result)
			case <-time.After(40 * time.Millisecond):
			}
		})
	}
}

func TestStrategySessionAttributionIsCaptured(t *testing.T) {
	manager := &Manager{}
	a := NewAutopilot(manager, nil)
	original := chameleon.Flavor{Base: 40 * time.Millisecond, MinPad: 100, MaxPad: 500}
	a.lastGenome = &chameleon.Genome{Flavor: original, Canary: true}
	report := a.captureStrategy(original, "original-node")
	a.lastGenome = &chameleon.Genome{Flavor: chameleon.Flavor{Base: 200 * time.Millisecond, MinPad: 200, MaxPad: 1400}}
	a.lastProf.TCPResetInjection = true
	report(chameleon.StrategyOutcome{Reason: "survived", DurationMS: chameleon.StrategySurvivalHorizon.Milliseconds(), SentBytes: 100, ReceivedBytes: 100})
	samples := a.survival.Snapshot()
	if len(samples) != 1 || !chameleon.SameStrategyFlavor(samples[0].Flavor, original) || !samples[0].Canary || samples[0].Context.TCPReset || samples[0].Context.Path != chameleon.StrategyPathID("original-node") {
		t.Fatalf("outcome attributed to later configuration: %+v", samples)
	}
	if a.canaries.Samples() != 1 || a.canaries.Survival() != 1 {
		t.Fatal("measured canary outcome missing")
	}
	a.OnSessionUp()
	if a.canaries.Samples() != 1 {
		t.Fatal("handshake counted as another survival sample")
	}
}

func TestStrategyRotationReservesBudgetBeforeMutation(t *testing.T) {
	entry := ServerEntry{Name: "fixture", Addr: "127.0.0.1:1", PubKey: "fixture-public", CFSeed: "fixture-seed"}
	manager := NewManager(&Store{Servers: []ServerEntry{entry}}, time.Second, time.Millisecond, "auto", "", nil)
	manager.activeAddr, manager.activePub = entry.Addr, entry.PubKey
	a := NewAutopilot(manager, nil)
	th := chameleon.DefaultTheta()
	th.LeakBits = 0
	a.theta = &th
	a.rotateStrategyFor(entry, true)
	if manager.genomeFlavor != nil || len(a.genomeHistory) != 0 || a.strategyRound != 0 {
		t.Fatal("zero budget still mutated live strategy")
	}
	fallback := entry
	fallback.CFSeed = ""
	originalName := manager.flavorName
	a.rotateStrategyFor(fallback, true)
	if manager.flavorName != originalName {
		t.Fatal("legacy rotation bypassed zero exploration budget")
	}
	th.LeakBits = 1
	a.leak = nil
	a.rotateStrategyFor(entry, true)
	if manager.genomeFlavor == nil || len(a.genomeHistory) != 1 || a.strategyRound != 1 {
		t.Fatal("permitted strategy not applied")
	}
	first := *manager.genomeFlavor
	a.rotateStrategyFor(entry, true)
	if !chameleon.SameStrategyFlavor(first, *manager.genomeFlavor) || len(a.genomeHistory) != 1 || a.strategyRound != 1 {
		t.Fatal("exhausted budget changed the strategy")
	}
}
