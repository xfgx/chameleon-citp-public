// Command cham-controlfab exercises the CITP Control Fabric end-to-end with
// REAL channels: real TLS bulletin, real DoH to public resolvers, real BGP
// via RIPEstat. Servers bind on all interfaces; the node address is
// auto-detected (CITP_NODE_IP overrides) and the PC address is auto-detected
// too (CITP_PC_IP overrides). Pass -nopause for scripted runs.
//
// Safe by design: carries only tiny control messages; BGP is read-only; CAR
// trigger is a benign token + local MockCensor; block-page signatures are
// configurable reference data, not real banned SNIs.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"chameleon/internal/chameleon"
)

func main() {
	nopause := flag.Bool("nopause", false, "do not wait for Enter before exit (for scripts)")
	flag.Parse()
	msg := "next-entry=auto;profile=refraction-tls"
	if flag.NArg() > 0 {
		msg = flag.Arg(0)
	}

	// --- node side: adaptive addressing, no hardcoded IPs ---
	nodeIP := chameleon.DetectNodeIP() // auto-detected from this machine (CITP_NODE_IP overrides)
	pcIP := chameleon.DetectPCIP()     // auto-detected client PC address (CITP_PC_IP overrides)
	fmt.Printf("node IP (auto) : %s\n", nodeIP)
	fmt.Printf("PC IP (auto)   : %s\n", pcIP)
	cdn := chameleon.NewCDNCacheStateChannel("0.0.0.0:18001")
	_ = cdn.WithTLS(nodeIP) // real self-signed HTTPS bound to the auto-detected node IP
	car := chameleon.NewCARChannel("0.0.0.0:18002")
	dns := chameleon.NewDNSBeacon("0.0.0.0:18053", "dd.phantom.lab", "c", 1)
	censor := chameleon.NewMockCensor("0.0.0.0:18000", "http://"+net.JoinHostPort(nodeIP, "18002"), "")

	go func() { _ = cdn.Serve() }()
	go func() { _ = car.Serve() }()
	go func() { _ = dns.Serve() }()
	go func() { _ = censor.Serve() }()
	time.Sleep(300 * time.Millisecond)

	cf := chameleon.NewControlFabric([]byte("master-seed"), cdn, car, dns, nil)
	ctx := context.Background()

	if err := cf.PublishControl(ctx, "demo", []byte(msg)); err != nil {
		fmt.Println("publish error:", err)
		os.Exit(1)
	}

	// --- client side, real channels over the auto-detected node address ---
	cli := chameleon.NewCDNCacheStateClient("https://" + net.JoinHostPort(nodeIP, "18001")).WithInsecureTLS()
	recovered, err := cf.RecoverControl(ctx, "demo", cli)
	if err != nil {
		fmt.Println("recover error:", err)
		os.Exit(1)
	}

	// DNS beacon (authoritative zone runs on the node)
	r := chameleon.NewDNSBeaconReader(nodeIP, 18053, "dd.phantom.lab", "c")
	beacon, _ := r.ReadChunk(0)

	// CAR verdict bits via the MockCensor (on-path model) on the node
	carReader := chameleon.NewCARReader("http://" + net.JoinHostPort(nodeIP, "18000")).
		WithBlockSignatures([]string{"<title>blocked</title>"})
	bits := carReader.ReadBits(0, 8)

	fmt.Println("=== CITP Control Fabric (real channels, adaptive addressing) ===")
	fmt.Printf("control message (published) : %q\n", msg)
	fmt.Printf("control message (recovered) : %q\n", string(recovered))
	fmt.Printf("bulletin transport          : real TLS (self-signed, node %s)\n", nodeIP)
	fmt.Printf("DNS beacon                  : %q\n", string(beacon))
	fmt.Printf("CAR verdict bits            : %v\n", bits)
	fmt.Printf("decoy origin (real)         : %s\n", cf.PickDecoy(0))

	// REAL internet data: DoH + BGP (no local dependency)
	fmt.Println("--- real internet data ---")
	if txts, err := cf.DoH("").ResolveTXT("google.com"); err == nil {
		fmt.Printf("DoH TXT for google.com      : %v (real Cloudflare 1.1.1.1)\n", txts)
	} else {
		fmt.Println("DoH google.com              : (offline)")
	}
	bgp := chameleon.NewBGPControlChannel("")
	if snap, err := bgp.BeaconSnapshot(ctx, "1.1.1.0/24"); err == nil {
		fmt.Printf("BGP AS-path snapshot        : %s (real RIPEstat)\n", snap)
		if routes, err := bgp.RoutingHistory(ctx, "1.1.1.0/24"); err == nil {
			fmt.Printf("BGP routing history         : %d origins (real RIPEstat)\n", len(routes))
		}
	} else {
		fmt.Println("BGP                         : (offline or unavailable)")
	}
	fmt.Println("=== done ===")

	_ = cdn.Shutdown()
	_ = car.Shutdown()
	_ = dns.Close()
	_ = censor.Shutdown()
	pauseBeforeExit(*nopause)
}

// pauseBeforeExit keeps the console window open on double-click so the
// results stay readable. Set -nopause or CITP_NO_PAUSE=1 for scripted runs.
func pauseBeforeExit(nopause bool) {
	if np, _ := os.LookupEnv("CITP_NO_PAUSE"); np != "" {
		nopause = true
	}
	if nopause {
		return
	}
	if st, err := os.Stdin.Stat(); err != nil || st.Mode()&os.ModeCharDevice == 0 {
		return // not an interactive console (piped) — do not block scripts
	}
	fmt.Print("\nГотово. Нажмите Enter для выхода...")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}
