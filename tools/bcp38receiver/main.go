package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const expectedSpoofedSource = "198.51.100.10"

type observation struct {
	First          time.Time
	Control, Spoof int
}
type store struct {
	mu   sync.Mutex
	seen map[string]observation
}

func (s *store) add(n string, c bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	for k, v := range s.seen {
		if now.Sub(v.First) > 10*time.Minute {
			delete(s.seen, k)
		}
	}
	v := s.seen[n]
	if v.First.IsZero() {
		v.First = now
	}
	if c {
		v.Control++
	} else {
		v.Spoof++
	}
	s.seen[n] = v
	if len(s.seen) > 4096 {
		for k := range s.seen {
			delete(s.seen, k)
			break
		}
	}
}
func (s *store) get(n string) (observation, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.seen[n]
	return v, ok
}
func validNonce(v string) bool {
	if len(v) != 32 {
		return false
	}
	_, e := hex.DecodeString(v)
	return e == nil
}
func main() {
	udpAddr := flag.String("udp", ":39838", "UDP probe listener")
	httpAddr := flag.String("http", ":39839", "HTTP result listener")
	flag.Parse()
	st := &store{seen: make(map[string]observation)}
	conn, e := net.ListenUDP("udp4", mustUDP(*udpAddr))
	if e != nil {
		log.Fatal(e)
	}
	defer conn.Close()
	go func() {
		buf := make([]byte, 256)
		for {
			n, src, e := conn.ReadFromUDP(buf)
			if e != nil {
				log.Printf("udp read: %v", e)
				continue
			}
			parts := strings.Split(string(buf[:n]), ":")
			if len(parts) != 3 || parts[0] != "CB38v2" || !validNonce(parts[2]) {
				continue
			}
			switch parts[1] {
			case "C":
				st.add(parts[2], true)
			case "S":
				if src.IP.Equal(net.ParseIP(expectedSpoofedSource)) {
					st.add(parts[2], false)
				}
			}
		}
	}()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		n := r.URL.Query().Get("nonce")
		if !validNonce(n) {
			http.Error(w, `{"error":"bad nonce"}`, 400)
			return
		}
		v, ok := st.get(n)
		out := map[string]any{"seen": ok, "count": v.Spoof, "control": v.Control, "spoof": v.Spoof}
		if ok {
			out["first_seen"] = v.First.Format(time.RFC3339Nano)
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	log.Printf("BCP38 receiver v2: UDP %s HTTP %s fixed spoof source %s", *udpAddr, *httpAddr, expectedSpoofedSource)
	srv := &http.Server{Addr: *httpAddr, Handler: mux, ReadHeaderTimeout: 3 * time.Second, IdleTimeout: 15 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
func mustUDP(a string) *net.UDPAddr {
	v, e := net.ResolveUDPAddr("udp4", a)
	if e != nil {
		panic(fmt.Sprintf("bad UDP address: %v", e))
	}
	return v
}
