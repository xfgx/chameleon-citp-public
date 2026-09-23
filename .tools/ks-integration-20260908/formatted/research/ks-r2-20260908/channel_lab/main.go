// Offline research only: no sockets, no credentials, no change to production KS.
package main

import (
	"chameleon/internal/chaossync"
	"crypto/sha256"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const scale = int64(1) << 48
const burn = 2048
const measure = 8192
const tail = 1024

type Field struct {
	ID     int      `json:"field"`
	Cohort string   `json:"cohort"`
	Mu     [8]int64 `json:"mu_raw"`
	E1     int64    `json:"eps1_raw"`
	E2     int64    `json:"eps2_raw"`
	X      [8]int64 `json:"initial_raw"`
	Y      [8]int64 `json:"observer_initial_raw"`
}
type Condition struct {
	Bits    int
	Loss    int
	Pattern string
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}
func hash64(prefix, tag string, i int) uint64 {
	d := sha256.Sum256([]byte(prefix + tag + "/" + strconv.Itoa(i)))
	return binary.BigEndian.Uint64(d[:8])
}
func fresh(k int) Field {
	f := Field{ID: k + 32, Cohort: "fresh-R2"}
	pre := "KS-R2-public-only/"
	f.E1 = int64(hash64(pre, "eps1", k) % 14073748835533)
	f.E2 = int64(hash64(pre, "eps2", k) % 14073748835533)
	for i := 0; i < 8; i++ {
		f.Mu[i] = 39*scale/10 + int64(hash64(pre, fmt.Sprintf("mu-%d", k), i)%28147497671065)
		f.X[i] = scale/20 + int64(hash64(pre, fmt.Sprintf("init-%d", k), i)%uint64(9*scale/10))
		f.Y[i] = scale/20 + int64(hash64(pre, fmt.Sprintf("follow-%d", k), i)%uint64(9*scale/10))
	}
	return f
}

// Generic Q0.b rounding with saturation, NOT the production modem codec.
func quant(x chaossync.Fxp, b int) chaossync.Fxp {
	if b == 48 {
		return x
	}
	shift := 48 - b
	code := (int64(x) + (int64(1) << (shift - 1))) >> shift
	max := (int64(1) << b) - 1
	if code < 0 {
		code = 0
	}
	if code > max {
		code = max
	}
	return chaossync.Fxp(code << shift)
}
func uniform(field, tick int) float64 {
	return float64(hash64("KS-R2-loss/", strconv.Itoa(field), tick)>>11) / 9007199254740992.0
}
func main() {
	src := flag.String("fields", "", "public R1 fields JSON")
	out := flag.String("out", "", "new output directory")
	flag.Parse()
	if *src == "" || *out == "" {
		panic("fields and out required")
	}
	if _, e := os.Stat(*out); !os.IsNotExist(e) {
		panic("output must not already exist")
	}
	check(os.MkdirAll(*out, 0700))
	started := time.Now()
	for _, b := range []int{12, 16, 24, 48} {
		for i := 0; i <= 10000; i++ {
			x := chaossync.Fxp(int64(i) * scale / 10000)
			q := quant(x, b)
			if q < 0 || q > chaossync.Fxp(scale) {
				panic("quantizer range")
			}
			if b == 48 && q != x {
				panic("identity quantizer")
			}
			if b < 48 && math.Abs(float64(q-x)) > float64(int64(1)<<(48-b)) {
				panic("quantizer bound")
			}
		}
	}
	raw, e := os.ReadFile(*src)
	check(e)
	var fs []Field
	check(json.Unmarshal(raw, &fs))
	if len(fs) != 32 {
		panic("expected R1 fields")
	}
	for i := range fs {
		fs[i].Cohort = "replication-R1"
	}
	for i := 0; i < 32; i++ {
		fs = append(fs, fresh(i))
	}
	raw, e = json.MarshalIndent(fs, "", "  ")
	check(e)
	check(os.WriteFile(filepath.Join(*out, "fields.json"), raw, 0600))
	var cs []Condition
	for _, b := range []int{12, 16, 24, 48} {
		cs = append(cs, Condition{b, 0, "none"})
		for _, loss := range []int{1, 5, 10} {
			for _, pat := range []string{"iid", "burst8"} {
				cs = append(cs, Condition{b, loss, pat})
			}
		}
	}
	f, e := os.Create(filepath.Join(*out, "channel_results.csv"))
	check(e)
	w := csv.NewWriter(f)
	check(w.Write([]string{"field", "cohort", "bits", "loss_percent_target", "pattern", "burn", "measure", "tail", "dropped_measure", "rms_tail", "max_abs_tail", "fraction_steps_above_0_01", "exact_tail"}))
	totalRows := 0
	for _, field := range fs {
		p := chaossync.FieldParams{Eps1: chaossync.Fxp(field.E1), Eps2: chaossync.Fxp(field.E2)}
		var x [8]chaossync.Fxp
		ys := make([][8]chaossync.Fxp, len(cs))
		for i := 0; i < 8; i++ {
			p.Mu[i] = chaossync.Fxp(field.Mu[i])
			p.Prev[i] = (i + 7) % 8
			p.Next[i] = (i + 1) % 8
			x[i] = chaossync.Fxp(field.X[i])
			for h := range ys {
				ys[h][i] = chaossync.Fxp(field.Y[i])
			}
		}
		sumsq := make([]float64, len(cs))
		maximum := make([]float64, len(cs))
		above := make([]int, len(cs))
		drops := make([]int, len(cs))
		exact := make([]bool, len(cs))
		for h := range exact {
			exact[h] = true
		}
		states := map[int]bool{}
		for _, loss := range []int{1, 5, 10} {
			states[loss] = uniform(field.ID, -loss) < float64(loss)/100
		}
		for tick := 0; tick < burn+measure; tick++ {
			p.Step(&x)
			u := uniform(field.ID, tick)
			for _, loss := range []int{1, 5, 10} {
				if states[loss] {
					states[loss] = u >= 1.0/8.0
				} else {
					states[loss] = u < (float64(loss)/100)/(8*(1-float64(loss)/100))
				}
			}
			var drives [4]int
			for j := 0; j < 4; j++ {
				drives[j] = (2*j + tick%2) % 8
			}
			for h, c := range cs {
				drop := c.Pattern == "iid" && u < float64(c.Loss)/100 || c.Pattern == "burst8" && states[c.Loss]
				if drop {
					p.Step(&ys[h])
					if tick >= burn {
						drops[h]++
					}
				} else {
					var vals [4]chaossync.Fxp
					for j, d := range drives {
						vals[j] = quant(x[d], c.Bits)
					}
					p.ObserverStepMulti(&ys[h], vals[:], chaossync.Fxp(950*scale/1000), drives[:])
				}
				if tick >= burn+measure-tail {
					bad := false
					for i, v := range ys[h] {
						if v < 0 || v > chaossync.Fxp(scale) {
							panic("state out of range")
						}
						delta := float64(v-x[i]) / float64(scale)
						a := math.Abs(delta)
						sumsq[h] += delta * delta
						if a > maximum[h] {
							maximum[h] = a
						}
						if a > 0.01 {
							bad = true
						}
						if v != x[i] {
							exact[h] = false
						}
					}
					if bad {
						above[h]++
					}
				}
			}
		}
		for h, c := range cs {
			exactInt := 0
			if exact[h] {
				exactInt = 1
			}
			row := []string{strconv.Itoa(field.ID), field.Cohort, strconv.Itoa(c.Bits), strconv.Itoa(c.Loss), c.Pattern, strconv.Itoa(burn), strconv.Itoa(measure), strconv.Itoa(tail), strconv.Itoa(drops[h]), strconv.FormatFloat(math.Sqrt(sumsq[h]/float64(tail*8)), 'g', 17, 64), strconv.FormatFloat(maximum[h], 'g', 17, 64), strconv.FormatFloat(float64(above[h])/tail, 'g', 17, 64), strconv.Itoa(exactInt)}
			check(w.Write(row))
			totalRows++
		}
		w.Flush()
		check(w.Error())
		fmt.Printf("field %d/64 complete\n", field.ID+1)
	}
	check(f.Close())
	info := map[string]any{"status": "PASS", "rows": totalRows, "fields": 64, "conditions": len(cs), "burn": burn, "measure": measure, "tail": tail, "quantizer_control_cases": 40004, "wall_seconds": time.Since(started).Seconds(), "model": "generic Q0.b; shared clock; whole-observation erasures; no wire/modem/network", "predeclared_success": "rms_tail < 0.001", "burst_model": "stationary initial two-state chain; mean dropped run 8; transition 0->1=p/(8*(1-p)), 1->0=1/8; shared public uniforms across precision levels"}
	raw, e = json.MarshalIndent(info, "", "  ")
	check(e)
	check(os.WriteFile(filepath.Join(*out, "run.json"), raw, 0600))
	fmt.Printf("PASS rows=%d wall=%s\n", totalRows, time.Since(started))
}
