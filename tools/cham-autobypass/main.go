// Command cham-autobypass runs the DPI profiler, then the LOCAL adaptive carrier
// selector, and prints a JSON BypassPlan. This is a local planner: it selects a
// carrier strategy based on the profile; it does NOT perform packet-level
// evasion. Every local action is marked mode:"local".
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"chameleon/internal/chameleon"
)

func main() {
	nopause := flag.Bool("nopause", false, "do not wait for Enter before exit (for scripts)")
	flag.Parse()
	cfg := chameleon.ProfilerConfig{
		ProbeDomains:    []string{"google.com", "cloudflare.com", "github.com"},
		ProbeHTTPURLs:   []string{"https://www.google.com/", "https://github.com/"},
		BlockSignatures: []string{"<title>blocked</title>", "доступ ограничен"},
		Timeout:         8 * time.Second,
	}
	if snis := os.Getenv("CITP_SNI_LIST"); snis != "" {
		cfg.SNIList = splitCSV(snis)
	}

	cf := chameleon.NewControlFabric([]byte("autobypass-seed"), nil, nil, nil, nil)
	ctx := context.Background()

	prof := cf.Profile(ctx, cfg)
	plan := chameleon.NewAdaptiveCarrierSelector(chameleon.DefaultCarrierProfiles()).Select(prof)

	fmt.Println("--- CensorProfile (measurement) ---")
	fmt.Println(chameleon.ProfilerJSON(prof))
	fmt.Println()
	fmt.Println("--- BypassPlan (local adaptive selector) ---")
	fmt.Println(chameleon.BypassPlanJSON(plan))
	if !plan.LocalPlan {
		fmt.Println("\nNOTE: plan includes infrastructure-gated actions (refraction station).")
	}
	pauseBeforeExit(*nopause)
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

func splitCSV(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == ',' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
		} else {
			cur += string(c)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
