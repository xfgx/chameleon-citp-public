package chameleon

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	StrategySurvivalHorizon = 45 * time.Second
	strategyHistoryLimit    = 256
	strategyHistoryMaxBytes = 1 << 20
	strategyHalfLife        = 6 * time.Hour
)

type StrategyContext struct {
	Path            string `json:"path"`
	DNSHijack       bool   `json:"dns_hijack"`
	TCPReset        bool   `json:"tcp_reset"`
	TLSInterference bool   `json:"tls_interference"`
	HTTPBlockPage   bool   `json:"http_block_page"`
}

func StrategyPathID(nodePublicKey string) string {
	sum := sha256.Sum256([]byte("citp-strategy-path-v1\x00" + nodePublicKey))
	return hex.EncodeToString(sum[:16])
}

type StrategyOutcome struct {
	Reason        string `json:"reason"`
	DurationMS    int64  `json:"duration_ms"`
	SentBytes     uint64 `json:"sent_bytes"`
	ReceivedBytes uint64 `json:"received_bytes"`
}

type StrategyObservation struct {
	Version  int             `json:"v"`
	AtUnixMS int64           `json:"at_unix_ms"`
	Context  StrategyContext `json:"context"`
	Flavor   Flavor          `json:"flavor"`
	Canary   bool            `json:"canary"`
	Outcome  StrategyOutcome `json:"outcome"`
}

func SameStrategyFlavor(a, b Flavor) bool {
	return a.Base == b.Base && a.Jitter == b.Jitter && a.MinPad == b.MinPad && a.MaxPad == b.MaxPad
}

func validStrategyFlavor(f Flavor) bool {
	return f.Base > 0 && f.Base <= 2*time.Second && f.Jitter >= 0 && f.Jitter <= 2*time.Second &&
		f.MinPad >= 0 && f.MaxPad >= f.MinPad && f.MaxPad <= 2048
}

func (o StrategyObservation) valid() bool {
	if o.Version != 1 || o.AtUnixMS <= 0 || len(o.Context.Path) != 32 || !validStrategyFlavor(o.Flavor) ||
		o.Outcome.DurationMS < 0 || o.Outcome.DurationMS > (24*time.Hour).Milliseconds() {
		return false
	}
	if _, err := hex.DecodeString(o.Context.Path); err != nil {
		return false
	}
	switch o.Outcome.Reason {
	case "survived", "dropped", "censored", "idle":
		return true
	default:
		return false
	}
}

// A handshake, idle connection, or local cancellation is not a survival label.
// These are observational connectivity results, not proof that DPI caused a drop.
func (o StrategyObservation) Learnable() bool {
	if !o.valid() {
		return false
	}
	switch o.Outcome.Reason {
	case "survived":
		return o.Outcome.DurationMS >= StrategySurvivalHorizon.Milliseconds() && o.Outcome.SentBytes > 0 && o.Outcome.ReceivedBytes > 0
	case "dropped":
		return o.Outcome.SentBytes > 0
	default:
		return false
	}
}

type StrategyEstimate struct {
	Mean       float64
	Support    float64
	Confidence float64
	StdDev     float64
	Samples    int
}

func (e StrategyEstimate) ScoreAdjustment() float64 {
	if e.Support < 4 {
		return 0
	}
	return 0.55 * e.Confidence * (e.Mean - 0.5)
}

type StrategySurvivalModel struct {
	mu      sync.Mutex
	history []StrategyObservation
}

func NewStrategySurvivalModel() *StrategySurvivalModel { return &StrategySurvivalModel{} }

func (m *StrategySurvivalModel) Record(o StrategyObservation) bool {
	if !o.valid() {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.history) == strategyHistoryLimit {
		copy(m.history, m.history[1:])
		m.history[len(m.history)-1] = o
	} else {
		m.history = append(m.history, o)
	}
	return true
}

func (m *StrategySurvivalModel) Snapshot() []StrategyObservation {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]StrategyObservation(nil), m.history...)
}

func strategyVector(f Flavor) [4]float64 {
	return [4]float64{float64(f.Base) / float64(300*time.Millisecond), float64(f.Jitter) / float64(300*time.Millisecond), float64(f.MinPad) / 1500, float64(f.MaxPad) / 1500}
}

// Only pre-trial path conditions and the candidate's actual parameters are inputs.
// Exogenous DPI verdicts and the outcome label are never candidate features.
func (m *StrategySurvivalModel) Estimate(f Flavor, context StrategyContext, now time.Time) StrategyEstimate {
	e := StrategyEstimate{Mean: 0.5, StdDev: math.Sqrt(1.0 / 12)}
	if !validStrategyFlavor(f) {
		return e
	}
	v := strategyVector(f)
	success := 0.0
	for _, o := range m.Snapshot() {
		if o.Context != context || !o.Learnable() {
			continue
		}
		age := now.Sub(time.UnixMilli(o.AtUnixMS))
		if age < 0 || age > 7*24*time.Hour {
			continue
		}
		x := strategyVector(o.Flavor)
		distance := 0.0
		for i := range v {
			distance += (v[i] - x[i]) * (v[i] - x[i])
		}
		weight := math.Exp(-8*distance) * math.Exp(-math.Ln2*float64(age)/float64(strategyHalfLife))
		if weight < 1e-6 {
			continue
		}
		e.Support += weight
		e.Samples++
		if o.Outcome.Reason == "survived" {
			success += weight
		}
	}
	e.Mean = (1 + success) / (2 + e.Support)
	e.Confidence = math.Min(1, e.Support/8)
	e.StdDev = math.Sqrt(e.Mean * (1 - e.Mean) / (3 + e.Support))
	return e
}

func LoadStrategyHistory(path string) ([]StrategyObservation, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > strategyHistoryMaxBytes {
		return nil, errors.New("strategy history exceeds size limit")
	}
	scanner := bufio.NewScanner(io.LimitReader(f, strategyHistoryMaxBytes+1))
	scanner.Buffer(make([]byte, 4096), 16*1024)
	model := NewStrategySurvivalModel()
	for scanner.Scan() {
		var o StrategyObservation
		if json.Unmarshal(scanner.Bytes(), &o) == nil {
			model.Record(o)
		}
	}
	return model.Snapshot(), scanner.Err()
}

func SaveStrategyHistory(path string, observations []StrategyObservation) error {
	if len(observations) > strategyHistoryLimit {
		observations = observations[len(observations)-strategyHistoryLimit:]
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".strategy-history-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	defer f.Close()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	encoder := json.NewEncoder(f)
	for _, o := range observations {
		if !o.valid() {
			return fmt.Errorf("invalid strategy observation")
		}
		if err := encoder.Encode(o); err != nil {
			return err
		}
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
