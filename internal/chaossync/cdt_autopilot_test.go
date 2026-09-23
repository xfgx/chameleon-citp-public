package chaossync

// cdt_autopilot_test.go — автопилот степени дисперсии: дисперсия растёт с риском,
// скорость честно падает (разброс интервалов). Доказываем trade-off.

import (
	"bytes"
	"testing"
)

func TestCDTAutopilotDispersion(t *testing.T) {
	master := bytes.Repeat([]byte{0x42}, 32)
	type row struct {
		risk         float64
		ports        int
		gapEnt, uniq float64
		meanGap      float64
	}
	var rows []row
	for _, risk := range []float64{0.0, 0.5, 1.0} {
		cfg := AutopilotGeom(risk)
		frag := NewFragmenter(master, 9, cfg)
		frag.Push(make([]byte, 200000))
		ports := map[int]bool{}
		tuples := map[[2]int]bool{}
		var gaps []int
		n := 0
		for {
			_, g, ok := frag.Emit()
			if !ok {
				_, g, ok = frag.EmitFinal()
				if !ok {
					break
				}
			}
			ports[g.DestPort] = true
			tuples[[2]int{g.SrcPort, g.DestPort}] = true
			gaps = append(gaps, g.GapUs)
			n++
		}
		sum := 0
		for _, g := range gaps {
			sum += g
		}
		r := row{risk, len(ports), entropyOf(gaps), float64(len(tuples)) / float64(n), float64(sum) / float64(len(gaps))}
		rows = append(rows, r)
		t.Logf("risk=%.1f: портов=%d, энтропия gap=%.2f бит, уник.tuple=%.3f, meanGap=%.0f мкс",
			r.risk, r.ports, r.gapEnt, r.uniq, r.meanGap)
	}
	lo, hi := rows[0], rows[2]
	if hi.ports <= lo.ports {
		t.Errorf("дисперсия портов не растёт с риском: risk0=%d risk1=%d", lo.ports, hi.ports)
	}
	if hi.gapEnt <= lo.gapEnt {
		t.Errorf("энтропия интервалов не растёт с риском: %.2f -> %.2f", lo.gapEnt, hi.gapEnt)
	}
	if hi.meanGap <= lo.meanGap {
		t.Errorf("ожидался рост mean gap с риском (цена скорости): %.0f -> %.0f", lo.meanGap, hi.meanGap)
	}
}
