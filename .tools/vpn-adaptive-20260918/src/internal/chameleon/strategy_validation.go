package chameleon

import (
	"errors"
	"math"
)

func (b *LeakBudget) Tighten(bits float64) {
	if bits < 0 || math.IsNaN(bits) || math.IsInf(bits, 0) { bits = 0 }
	b.mu.Lock()
	defer b.mu.Unlock()
	b.Total = min(b.Total, bits)
}

func ValidateTheta(th Theta) error {
	if th.Kind != ThetaKind || th.V != 1 { return errors.New("cf-theta: unsupported message or version") }
	if th.BaseMsLo < 5 || th.BaseMsHi < th.BaseMsLo || th.BaseMsHi > 2000 ||
		th.JitterLo < 0 || th.JitterHi < th.JitterLo || th.JitterHi > 2000 {
		return errors.New("cf-theta: invalid timing range")
	}
	if th.MinPadLo < 0 || th.MinPadHi < th.MinPadLo || th.MinPadHi > maxPaddingPayload-100 ||
		th.MaxPadLo < 0 || th.MaxPadHi < th.MaxPadLo || th.MaxPadHi > maxPaddingPayload || th.MaxPadHi < th.MinPadHi+100 {
		return errors.New("cf-theta: invalid padding range")
	}
	if math.IsNaN(th.CanaryFrac) || math.IsInf(th.CanaryFrac, 0) || th.CanaryFrac < 0 || th.CanaryFrac > 1 ||
		math.IsNaN(th.LeakBits) || math.IsInf(th.LeakBits, 0) || th.LeakBits < 0 || th.LeakBits > 4096 {
		return errors.New("cf-theta: invalid exploration budget")
	}
	return nil
}
