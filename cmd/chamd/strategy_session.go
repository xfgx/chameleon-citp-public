package main

import (
	"os"
	"path/filepath"
	"sync"
	"time"

	"chameleon/internal/chameleon"
)

type strategyObservedSession interface {
	Alive() bool
	PayloadStats() (uint64, uint64)
}

func observeStrategySession(session strategyObservedSession, horizon, interval time.Duration, report func(chameleon.StrategyOutcome)) func() {
	stop := make(chan struct{})
	var once sync.Once
	started := time.Now()
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		timer := time.NewTimer(horizon)
		defer timer.Stop()
		finish := func(reason string) {
			sent, received := session.PayloadStats()
			if reason == "survived" && (sent == 0 || received == 0) {
				reason = "idle"
			}
			report(chameleon.StrategyOutcome{Reason: reason, DurationMS: time.Since(started).Milliseconds(), SentBytes: sent, ReceivedBytes: received})
		}
		for {
			select {
			case <-stop:
				finish("censored")
				return
			case <-timer.C:
				select {
				case <-stop:
					finish("censored")
					return
				default:
				}
				if session.Alive() {
					finish("survived")
				} else {
					finish("dropped")
				}
				return
			case <-ticker.C:
				select {
				case <-stop:
					finish("censored")
					return
				default:
				}
				if !session.Alive() {
					finish("dropped")
					return
				}
			}
		}
	}()
	return func() { once.Do(func() { close(stop) }) }
}

// The manager's muxMu protects observer installation and cancellation.
func (m *Manager) startStrategyObservationLocked(mx *chameleon.Mux, flavor chameleon.Flavor, nodePublicKey string) {
	if m.cbr <= 0 || m.strategyObserver == nil {
		return
	}
	report := m.strategyObserver(flavor, nodePublicKey)
	if report == nil {
		return
	}
	m.cancelStrategyObservation = observeStrategySession(mx, chameleon.StrategySurvivalHorizon, time.Second, report)
}

func (m *Manager) cancelStrategyObservationLocked() {
	if m.cancelStrategyObservation != nil {
		m.cancelStrategyObservation()
		m.cancelStrategyObservation = nil
	}
}

func (a *Autopilot) strategyContext(nodePublicKey string) chameleon.StrategyContext {
	a.mu.Lock()
	defer a.mu.Unlock()
	p := a.lastProf
	return chameleon.StrategyContext{Path: chameleon.StrategyPathID(nodePublicKey), DNSHijack: p.DNSLikelyHijack, TCPReset: p.TCPResetInjection, TLSInterference: p.TLSInterference, HTTPBlockPage: p.HTTPBlockPage}
}

func (a *Autopilot) captureStrategy(flavor chameleon.Flavor, nodePublicKey string) func(chameleon.StrategyOutcome) {
	context := a.strategyContext(nodePublicKey)
	a.mu.Lock()
	canary := a.lastGenome != nil && chameleon.SameStrategyFlavor(a.lastGenome.Flavor, flavor) && a.lastGenome.Canary
	model := a.survival
	a.mu.Unlock()
	return func(outcome chameleon.StrategyOutcome) {
		o := chameleon.StrategyObservation{Version: 1, AtUnixMS: time.Now().UnixMilli(), Context: context, Flavor: flavor, Canary: canary, Outcome: outcome}
		if !model.Record(o) {
			return
		}
		a.strategyHistoryMu.Lock()
		a.mu.Lock()
		dir := a.dataDir
		a.mu.Unlock()
		if dir != "" {
			if err := chameleon.SaveStrategyHistory(filepath.Join(dir, "strategy-outcomes.jsonl"), model.Snapshot()); err != nil {
				a.m.logf("autopilot: журнал устойчивости: %v", err)
			}
		}
		a.strategyHistoryMu.Unlock()
		if !o.Learnable() {
			return
		}
		a.m.logf("autopilot: наблюдение стратегии base=%s pad=%d..%d: %s, %d мс, полезные байты %d/%d (не диагноз DPI)", flavor.Base, flavor.MinPad, flavor.MaxPad, outcome.Reason, outcome.DurationMS, outcome.SentBytes, outcome.ReceivedBytes)
		if canary {
			a.canaries.Record(outcome.Reason == "survived")
			if a.canaries.ShouldBumpEpoch(0.6, 5) {
				go a.profileAndApply("ухудшение измеренной устойчивости канареек")
			}
		}
	}
}

func (a *Autopilot) loadStrategyHistory(dir string) {
	if dir == "" {
		return
	}
	a.strategyHistoryMu.Lock()
	defer a.strategyHistoryMu.Unlock()
	observations, err := chameleon.LoadStrategyHistory(filepath.Join(dir, "strategy-outcomes.jsonl"))
	if err != nil {
		if !os.IsNotExist(err) {
			a.m.logf("autopilot: загрузка наблюдений стратегий: %v", err)
		}
		return
	}
	for _, observation := range observations {
		a.survival.Record(observation)
	}
}
