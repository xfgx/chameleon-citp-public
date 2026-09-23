package chaossync

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"testing"
)

// Public synthetic fixture, not a production key or the DeriveFieldClass distribution.
//
//go:embed testdata/ks_r1_fields.json
var ksResearchFieldsJSON []byte

type ksResearchField struct {
	ID int          `json:"field"`
	Mu [Sites]int64 `json:"mu_raw"`
	E1 int64        `json:"eps1_raw"`
	E2 int64        `json:"eps2_raw"`
	X  [Sites]int64 `json:"initial_raw"`
	Y  [Sites]int64 `json:"observer_initial_raw"`
}

// TestKSResearchLengthContract pins only the current Seal-level length contract.
// It is not an assertion that traffic is indistinguishable or that padding is forbidden.
// A future intentional wire-format revision must revise this test and its evidence.
func TestKSResearchLengthContract(t *testing.T) {
	cases := 0
	for seed := 0; seed < 16; seed++ {
		master := sha256.Sum256([]byte(fmt.Sprintf("KS-R1-public-only-native-%d", seed)))
		dir := "c2n"
		if seed%2 == 1 {
			dir = "n2c"
		}
		tx, rx := NewSender(master[:], 424242, dir), NewReceiver(master[:], 424242, dir)
		for n := 0; n <= 1500; n++ {
			plain := bytes.Repeat([]byte{byte(seed + n)}, n)
			wire := tx.Seal(plain)
			if len(wire) != n+28 {
				t.Fatalf("seed=%d input=%d Seal=%d; expected input+28", seed, n, len(wire))
			}
			got, ok := rx.Ingest(wire)
			if !ok || !bytes.Equal(got, plain) {
				t.Fatalf("roundtrip seed=%d length=%d", seed, n)
			}
			cases++
		}
	}
	t.Logf("%d public cases: Seal=input+28, exact roundtrip", cases)
}

// TestKSResearchScheduleRegression repeats a finite, noiseless observation, not a
// global synchronization theorem. This does not alter the KS key schedule.
func TestKSResearchScheduleRegression(t *testing.T) {
	if testing.Short() {
		t.Skip("finite-window CML regression omitted in short mode")
	}
	var fields []ksResearchField
	if err := json.Unmarshal(ksResearchFieldsJSON, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 32 {
		t.Fatalf("expected 32 public fields, got %d", len(fields))
	}
	var successes [2]int
	c := Fxp(int64(950) * (int64(1) << 48) / 1000)
	for _, f := range fields {
		p := FieldParams{Eps1: Fxp(f.E1), Eps2: Fxp(f.E2)}
		var x [Sites]Fxp
		var ys [2][Sites]Fxp
		for i := 0; i < Sites; i++ {
			p.Mu[i] = Fxp(f.Mu[i])
			p.Prev[i] = (i + Sites - 1) % Sites
			p.Next[i] = (i + 1) % Sites
			x[i] = Fxp(f.X[i])
			ys[0][i] = Fxp(f.Y[i])
			ys[1][i] = Fxp(f.Y[i])
		}
		exact := [2]bool{true, true}
		for tick := 0; tick < 2048+8192; tick++ {
			p.Step(&x)
			for mode := 0; mode < 2; mode++ {
				var drives [MaxChan]int
				var values [MaxChan]Fxp
				offset := 0
				if mode == 1 {
					offset = tick % 2
				}
				for j := 0; j < MaxChan; j++ {
					drives[j] = (2*j + offset) % Sites
					values[j] = x[drives[j]]
				}
				p.ObserverStepMulti(&ys[mode], values[:], c, drives[:])
				if tick >= 2048+8192-1024 && ys[mode] != x {
					exact[mode] = false
				}
			}
		}
		for mode := range exact {
			if exact[mode] {
				successes[mode]++
			}
		}
	}
	if successes != [2]int{0, 32} {
		t.Fatalf("terminal exact-match fields: fixed4=%d alternate4=%d; expected 0 and 32", successes[0], successes[1])
	}
	t.Logf("terminal 1024-step exact equality: fixed4=%d/32 alternate4=%d/32", successes[0], successes[1])
}
