package chameleon

import (
	"math"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func survivalFixture(f Flavor, context StrategyContext, now time.Time, success bool) StrategyObservation {
	reason := "dropped"
	if success {
		reason = "survived"
	}
	return StrategyObservation{Version: 1, AtUnixMS: now.Add(-time.Millisecond).UnixMilli(), Context: context, Flavor: f, Outcome: StrategyOutcome{Reason: reason, DurationMS: StrategySurvivalHorizon.Milliseconds(), SentBytes: 100, ReceivedBytes: 200}}
}

func TestStrategySurvivalCandidateSpecific(t *testing.T) {
	model := NewStrategySurvivalModel()
	now := time.Now()
	context := StrategyContext{Path: StrategyPathID("test-node"), TCPReset: true}
	good := Flavor{Base: 40 * time.Millisecond, Jitter: 20 * time.Millisecond, MinPad: 100, MaxPad: 500}
	bad := Flavor{Base: 280 * time.Millisecond, Jitter: 20 * time.Millisecond, MinPad: 200, MaxPad: 1400}
	for range 24 {
		model.Record(survivalFixture(good, context, now, true))
		model.Record(survivalFixture(bad, context, now, false))
	}
	a, b := model.Estimate(good, context, now), model.Estimate(bad, context, now)
	if a.Mean < 0.85 || b.Mean > 0.15 || a.ScoreAdjustment() <= b.ScoreAdjustment() {
		t.Fatalf("candidates not distinguished: good=%+v bad=%+v", a, b)
	}
	context.Path = StrategyPathID("different-node")
	if e := model.Estimate(good, context, now); e.Mean != 0.5 || e.Support != 0 {
		t.Fatalf("cross-path evidence leaked: %+v", e)
	}
}

func TestStrategySurvivalNoHandshakeOrCancellationLabels(t *testing.T) {
	model := NewStrategySurvivalModel()
	now := time.Now()
	context := StrategyContext{Path: StrategyPathID("test-node")}
	f := Flavor{Base: time.Millisecond * 40, MinPad: 100, MaxPad: 500}
	for _, reason := range []string{"idle", "censored", "survived", "dropped"} {
		o := survivalFixture(f, context, now, true)
		o.Outcome.Reason = reason
		o.Outcome.SentBytes, o.Outcome.ReceivedBytes = 0, 0
		if o.Learnable() {
			t.Fatalf("%s without payload became a label", reason)
		}
		model.Record(o)
	}
	o := survivalFixture(f, context, now, true)
	o.Outcome.DurationMS = 1
	if o.Learnable() {
		t.Fatal("handshake-length session counted as survival")
	}
	model.Record(o)
	if estimate := model.Estimate(f, context, now); estimate.Support != 0 || estimate.ScoreAdjustment() != 0 {
		t.Fatalf("unobserved evidence influenced ranking: %+v", estimate)
	}
}

func TestStrategySurvivalRecencyAndPersistence(t *testing.T) {
	model := NewStrategySurvivalModel()
	now := time.Now()
	context := StrategyContext{Path: StrategyPathID("test-node")}
	f := Flavor{Base: 40 * time.Millisecond, MinPad: 100, MaxPad: 500}
	for i := 0; i < strategyHistoryLimit+20; i++ {
		model.Record(survivalFixture(f, context, now, true))
	}
	if len(model.Snapshot()) != strategyHistoryLimit {
		t.Fatal("history unbounded")
	}
	fresh := model.Estimate(f, context, now)
	old := model.Estimate(f, context, now.Add(72*time.Hour))
	if old.Support >= fresh.Support/100 || old.ScoreAdjustment() != 0 {
		t.Fatalf("old evidence did not decay: fresh=%+v old=%+v", fresh, old)
	}
	path := filepath.Join(t.TempDir(), "outcomes.jsonl")
	if err := SaveStrategyHistory(path, model.Snapshot()); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadStrategyHistory(path)
	if err != nil || len(loaded) != strategyHistoryLimit {
		t.Fatalf("history roundtrip: %d %v", len(loaded), err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("history permissions: %v %v", info, err)
	}
}

func TestStrategyModelConcurrentAccess(t *testing.T) {
	model := NewStrategySurvivalModel()
	now := time.Now()
	context := StrategyContext{Path: StrategyPathID("test-node")}
	f := Flavor{Base: 40 * time.Millisecond, MinPad: 100, MaxPad: 500}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(success bool) {
			defer wg.Done()
			for range 40 {
				model.Record(survivalFixture(f, context, now, success))
				model.Estimate(f, context, now)
			}
		}(i%2 == 0)
	}
	wg.Wait()
	if n := len(model.Snapshot()); n != strategyHistoryLimit {
		t.Fatalf("history length %d", n)
	}
}

func TestStrategyThetaAndBudgetFailClosed(t *testing.T) {
	if err := ValidateTheta(DefaultTheta()); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Theta){
		func(th *Theta) { th.BaseMsLo = 0 },
		func(th *Theta) { th.BaseMsHi = -1 },
		func(th *Theta) { th.JitterHi = 1 << 30 },
		func(th *Theta) { th.MinPadLo = -1 },
		func(th *Theta) { th.MaxPadHi = 1 << 30 },
		func(th *Theta) { th.CanaryFrac = math.NaN() },
		func(th *Theta) { th.LeakBits = math.Inf(1) },
		func(th *Theta) { th.V = 100 },
	} {
		th := DefaultTheta()
		mutate(&th)
		if ValidateTheta(th) == nil {
			t.Fatalf("invalid theta accepted: %+v", th)
		}
	}
	for _, value := range []float64{0, -1, math.NaN(), math.Inf(1)} {
		budget := NewLeakBudget(1, value)
		if budget.TrySpend(1) || budget.Remaining() != 0 {
			t.Fatalf("invalid/zero budget allowed exposure: %+v", budget)
		}
	}
	budget := NewLeakBudget(1, 3)
	if budget.TrySpend(math.NaN()) || budget.TrySpend(math.Inf(1)) || budget.TrySpend(-1) || budget.Remaining() != 3 {
		t.Fatal("invalid spend changed budget")
	}
	if !budget.TrySpend(1) {
		t.Fatal("valid spend rejected")
	}
	budget.Tighten(0)
	budget.Tighten(100)
	if budget.TrySpend(1) || budget.Remaining() != 0 || budget.SpentFrac() != 1 {
		t.Fatal("tightened budget was bypassed or replenished")
	}
}
