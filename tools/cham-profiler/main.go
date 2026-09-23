// Command cham-profiler runs the CITP DPI auto-profiler and prints a JSON
// CensorProfile. This is a measurement / diagnostics tool (OONI-style): it
// detects DNS poisoning, TCP reset injection, TLS/SNI interference, HTTP
// block pages, and attempts TTL-based censor localization. It does NOT evade.
//
// Probe domains / SNIs are operator-curated (like OONI's Citizen Lab lists);
// defaults are benign real domains that only exercise the probe machinery.
package main

import (
	"bufio"
	"context"
	"encoding/json"
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

	cf := chameleon.NewControlFabric([]byte("profiler-seed"), nil, nil, nil, nil)
	ctx := context.Background()
	prof := cf.Profile(ctx, cfg)

	out, _ := json.MarshalIndent(prof, "", "  ")
	fmt.Println(string(out))
	fmt.Println("---")
	fmt.Println(chameleon.ProfilerJSON(prof))
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
