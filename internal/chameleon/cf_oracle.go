package chameleon

// cf_oracle.go — Verdict oracle: builds a shared codebook + schedule from
// probe results and a seeded PRNG, so node and client stay in sync about which
// slot/channel/carrier to use at each tick without exchanging the schedule.

import "math/rand"

// VerdictOracle derives a deterministic codebook + schedule from a seed.
type VerdictOracle struct {
	censorURL string
	token     string
	seed      int64
	rng       *rand.Rand
}

// NewVerdictOracle constructs an oracle. censorURL is the on-path censor (or
// MockCensor in the lab).
func NewVerdictOracle(censorURL string, seed int64) *VerdictOracle {
	return &VerdictOracle{censorURL: censorURL, token: CARForbiddenToken, seed: seed, rng: rand.New(rand.NewSource(seed))}
}

// Codebook maps a slot index to the probe seq used to signal a 1-bit.
func (o *VerdictOracle) Codebook(size int) map[int]int {
	out := make(map[int]int, size)
	for i := 0; i < size; i++ {
		out[i] = 1000 + i
	}
	return out
}

// ScheduleEntry is a (tick, channel) assignment.
type ScheduleEntry struct {
	Tick    int
	Channel string
}

// Schedule produces a deterministic schedule over the available channels.
func (o *VerdictOracle) Schedule(ticks int, channels []string) []ScheduleEntry {
	sched := make([]ScheduleEntry, 0, ticks)
	for t := 0; t < ticks; t++ {
		ch := channels[t%len(channels)]
		sched = append(sched, ScheduleEntry{Tick: t, Channel: ch})
	}
	return sched
}

// BeaconBits returns a PRNG-derived slice of signaling bits (for lab demo).
func (o *VerdictOracle) BeaconBits(n int) []uint8 {
	out := make([]uint8, n)
	for i := range out {
		out[i] = uint8(o.rng.Intn(2))
	}
	return out
}
