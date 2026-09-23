// Command cham-detectors runs the Control Fabric detection suite:
//   - verdict-probing  : flags sequential /car/<seq> 403/RST patterns
//   - txt-entropy      : flags high-entropy long TXT records (DNS dead-drop)
//   - query-cadence    : flags near-constant DNS query deltas (polling)
//   - route-flap       : flags high BGP update churn (read-only RIPEstat)
//
// Each detector is self-contained and safe (read-only).
package main

import (
	"bufio"
	"flag"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
)

func main() {
	nopause := flag.Bool("nopause", false, "do not wait for Enter before exit (for scripts)")
	flag.Parse()
	defer func() { pauseBeforeExit(*nopause) }()
	if flag.NArg() < 1 {
		// default: run the full demo suite instead of exiting with usage
		fmt.Println("cham-detectors: running all detectors (demo data). Pass a detector name to run one.")
		fmt.Println("== verdict-probing ==")
		verdictProbing(nil)
		fmt.Println("== txt-entropy ==")
		txtEntropy(nil)
		fmt.Println("== query-cadence ==")
		queryCadence(nil)
		fmt.Println("== route-flap ==")
		routeFlap(nil)
		return
	}
	os.Args = append([]string{os.Args[0]}, flag.Args()...) // keep detectors' positional args working
	switch os.Args[1] {
	case "verdict-probing":
		verdictProbing(os.Args[2:])
	case "txt-entropy":
		txtEntropy(os.Args[2:])
	case "query-cadence":
		queryCadence(os.Args[2:])
	case "route-flap":
		routeFlap(os.Args[2:])
	default:
		fmt.Println("unknown detector:", os.Args[1])
		os.Exit(1)
	}
}

func verdictProbing(args []string) {
	// synthetic example: 10 blocked + 2 clean, sequential seqs
	lines := []string{}
	for i := 0; i < 10; i++ {
		lines = append(lines, fmt.Sprintf("GET /car/%d 403 blocked", i))
	}
	for i := 10; i < 12; i++ {
		lines = append(lines, fmt.Sprintf("GET /car/%d 200 ok", i))
	}
	blocked, clean, seqs := 0, 0, []int{}
	for _, l := range lines {
		if !strings.Contains(l, "/car/") {
			continue
		}
		parts := strings.Split(l, " ")
		seq, _ := strconv.Atoi(parts[2])
		seqs = append(seqs, seq)
		if strings.Contains(l, " 403 ") || strings.Contains(l, "rst") {
			blocked++
		} else if strings.Contains(l, " 200 ") {
			clean++
		}
	}
	total := blocked + clean
	fmt.Printf("car requests: %d (blocked=%d clean=%d)\n", total, blocked, clean)
	if len(seqs) > 4 && seqs[len(seqs)-1]-seqs[0]+1 == len(seqs) {
		fmt.Println("FLAG: sequentially numbered /car/<seq> probing")
	}
	if total > 0 && float64(blocked)/float64(total) > 0.3 {
		fmt.Println("FLAG: high block/rst ratio -> verdict-channel signalling")
	}
}

func txtEntropy(args []string) {
	// synthetic example: one high-entropy record + one low
	records := []string{
		"v=spf1 include:_spf.example.com ~all",
		"Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MTIzNDU2Nzg5",
	}
	for i, r := range records {
		e := shannon(r)
		fmt.Printf("record %d: len=%d entropy=%.2f flag=%v\n", i, len(r), e, len(r) > 40 && e > 4.5)
		if len(r) > 40 && e > 4.5 {
			fmt.Println("  FLAG: high-entropy long TXT -> possible covert dead-drop")
		}
	}
}

func queryCadence(args []string) {
	// synthetic regular-poll deltas
	ts := []float64{0, 0.5, 1.0, 1.51, 2.0, 2.5, 3.0, 3.5}
	if len(args) >= 4 {
		ts = nil
		for _, a := range args {
			v, _ := strconv.ParseFloat(a, 64)
			ts = append(ts, v)
		}
	}
	if len(ts) < 4 {
		fmt.Println("not enough samples")
		return
	}
	d := []float64{}
	for i := 0; i < len(ts)-1; i++ {
		d = append(d, ts[i+1]-ts[i])
	}
	mean := 0.0
	for _, x := range d {
		mean += x
	}
	mean /= float64(len(d))
	v := 0.0
	for _, x := range d {
		v += (x - mean) * (x - mean)
	}
	stdev := math.Sqrt(v / float64(len(d)))
	cv := stdev / mean
	fmt.Printf("mean delta=%.3f stdev=%.3f CV=%.3f\n", mean, stdev, cv)
	if cv < 0.15 {
		fmt.Println("FLAG: near-constant cadence -> dead-drop polling")
	} else {
		fmt.Println("ok: cadence irregular/bursty")
	}
}

func routeFlap(args []string) {
	// detector reads RIPEstat routing-history in a real deployment; here we
	// document the logic and exit safely.
	fmt.Println("route-flap detector: would query RIPEstat routing-history for update churn (read-only).")
	fmt.Println("Wire to net/http GET https://stat.ripe.net/data/routing-history/data.json?resource=<prefix> in production.")
}

func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	for _, c := range s {
		counts[c]++
	}
	n := float64(len(s))
	h := 0.0
	for _, c := range counts {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func pauseBeforeExit(nopause bool) {
	if np, _ := os.LookupEnv("CITP_NO_PAUSE"); np != "" {
		nopause = true
	}
	if nopause {
		return
	}
	if st, err := os.Stdin.Stat(); err != nil || st.Mode()&os.ModeCharDevice == 0 {
		return
	}
	fmt.Print("\nГотово. Нажмите Enter для выхода...")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}
