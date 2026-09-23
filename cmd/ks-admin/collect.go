//go:build linux

// Сбор статистики из четырёх источников ядра и служб:
//  1. /run/ks-hub/status.json      - пользователи многопользовательского хаба
//  2. /sys/class/net/*/statistics  - байты/пакеты/ошибки туннелей
//  3. /proc/net/nf_conntrack       - адреса устройств на проводе (без полезной нагрузки)
//  4. journald по юнитам        - счётчики стадий и сообщения об ошибках
//
// Полезная нагрузка пакетов нигде не читается.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const conntrackPath = "/proc/net/nf_conntrack"

var (
	reKV       = regexp.MustCompile(`([\p{L}\p{N}_]+)=(\S*)`)
	reGoPrefix = regexp.MustCompile(`^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(\.\d+)?\s+`)
	reErrLine  = regexp.MustCompile(`(?i)ошибк|не удалось|отказ|нет маршрута|panic|fatal|error|failed|refused|timed out|timeout|exit status`)
	reWarnLine = regexp.MustCompile(`(?i)внимание|предупрежд|warn|fail-closed|мимо туннеля|пропускаю`)
)

// ---------- хаб ----------

func readHubStatus(path string) (*hubStatus, error) {
	if path == "" {
		return nil, fmt.Errorf("путь к status.json не задан")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("%s пуст", path)
	}
	h := &hubStatus{}
	if err := json.Unmarshal(b, h); err != nil {
		return nil, err
	}
	if h.Totals == nil {
		h.Totals = map[string]uint64{}
	}
	return h, nil
}

// ---------- туннельные интерфейсы ----------

func readIfaces(names []string) []ifStat {
	out := make([]ifStat, 0, len(names))
	for _, n := range names {
		base := filepath.Join("/sys/class/net", n)
		if _, err := os.Stat(base); err != nil {
			out = append(out, ifStat{Name: n})
			continue
		}
		st := filepath.Join(base, "statistics")
		out = append(out, ifStat{
			Name:    n,
			Up:      ifaceUp(base),
			RxBytes: readU(filepath.Join(st, "rx_bytes")),
			TxBytes: readU(filepath.Join(st, "tx_bytes")),
			RxPkts:  readU(filepath.Join(st, "rx_packets")),
			TxPkts:  readU(filepath.Join(st, "tx_packets")),
			RxErrs:  readU(filepath.Join(st, "rx_errors")),
			TxErrs:  readU(filepath.Join(st, "tx_errors")),
			RxDrop:  readU(filepath.Join(st, "rx_dropped")),
			TxDrop:  readU(filepath.Join(st, "tx_dropped")),
		})
	}
	return out
}

func ifaceUp(base string) bool {
	b, err := os.ReadFile(filepath.Join(base, "operstate"))
	if err != nil {
		return false
	}
	s := strings.TrimSpace(string(b))
	return s == "up" || s == "unknown"
}

func readU(path string) uint64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// ---------- адреса устройств на проводе ----------

// enableConntrackAcct включает учёт пакетов/байт в conntrack, чтобы видеть
// объёмы по каждому адресу. На содержимое пакетов это не влияет.
func enableConntrackAcct() {
	p := "/proc/sys/net/netfilter/nf_conntrack_acct"
	b, err := os.ReadFile(p)
	if err != nil {
		log.Printf("учёт conntrack недоступен (%v) - объёмы по адресам будут пустыми", err)
		return
	}
	if strings.TrimSpace(string(b)) == "1" {
		return
	}
	if err := os.WriteFile(p, []byte("1\n"), 0o644); err != nil {
		log.Printf("не удалось включить nf_conntrack_acct: %v", err)
		return
	}
	log.Printf("включён учёт пакетов/байт в conntrack (nf_conntrack_acct=1)")
}

// ctBin находит утилиту conntrack. В современных ядрах /proc/net/nf_conntrack
// отключён, поэтому основной источник - conntrack-tools.
func ctBin() string {
	for _, p := range []string{"/usr/sbin/conntrack", "/sbin/conntrack", "/usr/bin/conntrack"} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	if p, err := exec.LookPath("conntrack"); err == nil {
		return p
	}
	return ""
}

// readConntrack возвращает живые UDP-потоки к портам провода: адреса,
// порты и счётчики. Полезная нагрузка не читается.
func readConntrack(ports map[int]string, maxRows int) []connRow {
	if len(ports) == 0 {
		return nil
	}
	if bin := ctBin(); bin != "" {
		out, err := exec.Command(bin, "-L", "-p", "udp").Output()
		if len(out) > 0 || err == nil {
			return parseConntrack(strings.Split(strings.TrimRight(string(out), "\n"), "\n"), ports, maxRows)
		}
	}
	b, err := os.ReadFile(conntrackPath)
	if err != nil {
		return nil
	}
	return parseConntrack(strings.Split(strings.TrimRight(string(b), "\n"), "\n"), ports, maxRows)
}

func parseConntrack(lines []string, ports map[int]string, maxRows int) []connRow {
	out := make([]connRow, 0, 32)
	for _, ln := range lines {
		if !strings.Contains(ln, "udp") {
			continue
		}
		var r connRow
		var pkts, byts uint64
		for _, tk := range strings.Fields(ln) {
			switch {
			case strings.HasPrefix(tk, "src=") && r.Src == "":
				r.Src = tk[len("src="):]
			case strings.HasPrefix(tk, "dst=") && r.Dst == "":
				r.Dst = tk[len("dst="):]
			case strings.HasPrefix(tk, "sport=") && r.Sport == 0:
				r.Sport, _ = strconv.Atoi(tk[len("sport="):])
			case strings.HasPrefix(tk, "dport=") && r.Port == 0:
				r.Port, _ = strconv.Atoi(tk[len("dport="):])
			case strings.HasPrefix(tk, "packets="):
				if n, err := strconv.ParseUint(tk[len("packets="):], 10, 64); err == nil {
					pkts += n
				}
			case strings.HasPrefix(tk, "bytes="):
				if n, err := strconv.ParseUint(tk[len("bytes="):], 10, 64); err == nil {
					byts += n
				}
			}
		}
		lbl, ok := ports[r.Port]
		if !ok {
			continue
		}
		r.Service = lbl
		r.Packets = pkts
		r.Bytes = byts
		out = append(out, r)
		if maxRows > 0 && len(out) >= maxRows {
			break
		}
	}
	return out
}

// ---------- журнал служб ----------

func journalPoll(first bool) {
	for _, u := range unitList {
		lines, cursor := journalRead(u, first)
		if cursor != "" {
			setCursor(u, cursor)
		}
		st := getSvc(u)
		st.Unit = u
		st.Active = unitActive(u)
		for _, ln := range lines {
			ts, msg := splitJournalLine(ln)
			if i := strings.Index(msg, "стадии:"); i >= 0 {
				nums, lastRx, wire := parseStage(msg[i+len("стадии:"):])
				if len(nums) > 0 {
					st.Nums = nums
					st.LastRxSec = lastRx
					st.Wire = wire
					st.At = ts
				}
				continue
			}
			if strings.HasPrefix(msg, "хаб: ") {
				continue // сводка хаба берётся из status.json
			}
			if lvl := classify(msg); lvl != "" {
				addEventAt(lvl, u, msg, ts)
			}
		}
		putSvc(u, st)
	}
}

func journalRead(unit string, first bool) ([]string, string) {
	args := []string{"-u", unit, "--no-pager", "--output=short-iso", "--show-cursor"}
	cur := getCursor(unit)
	if cur != "" && !first {
		args = append(args, "--after-cursor", cur, "--lines", "3000")
	} else {
		args = append(args, "--lines", "30")
	}
	out, err := exec.Command("journalctl", args...).Output()
	if err != nil && len(out) == 0 {
		return nil, ""
	}
	cursor := ""
	res := make([]string, 0, 16)
	for _, ln := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if strings.HasPrefix(ln, "-- cursor: ") {
			cursor = strings.TrimSpace(strings.TrimPrefix(ln, "-- cursor: "))
			continue
		}
		if ln == "" || strings.HasPrefix(ln, "-- ") {
			continue
		}
		res = append(res, ln)
	}
	return res, cursor
}

func unitActive(unit string) bool {
	out, _ := exec.Command("systemctl", "is-active", unit).Output()
	return strings.TrimSpace(string(out)) == "active"
}

func splitJournalLine(ln string) (time.Time, string) {
	ts := time.Now()
	rest := ln
	if sp := strings.IndexByte(ln, ' '); sp > 0 {
		if t, err := time.Parse(time.RFC3339, ln[:sp]); err == nil {
			ts = t
			rest = ln[sp+1:]
		}
	}
	if i := strings.Index(rest, "]: "); i >= 0 {
		rest = rest[i+3:]
	}
	rest = strings.TrimSpace(rest)
	if strings.HasPrefix(rest, "[") {
		if i := strings.Index(rest, "] "); i >= 0 && i < 40 {
			rest = rest[i+2:]
		}
	}
	rest = reGoPrefix.ReplaceAllString(rest, "")
	return ts, strings.TrimSpace(rest)
}

func parseStage(s string) (map[string]uint64, int64, string) {
	nums := map[string]uint64{}
	lastRx := int64(-1)
	wire := ""
	for _, m := range reKV.FindAllStringSubmatch(s, -1) {
		k, v := m[1], m[2]
		switch k {
		case "lastRx":
			if v != "" && v != "нет" {
				if n, err := strconv.Atoi(strings.TrimSuffix(v, "s")); err == nil {
					lastRx = int64(n)
				}
			}
		case "провод", "wire":
			wire = v
		case "v6":
			if v != "" && v != "-" {
				nums["v6"] = 1
			}
		default:
			if n, err := strconv.ParseUint(v, 10, 64); err == nil {
				nums[k] = n
			}
		}
	}
	return nums, lastRx, wire
}

func classify(msg string) string {
	if msg == "" {
		return ""
	}
	if reErrLine.MatchString(msg) {
		return "ERROR"
	}
	if reWarnLine.MatchString(msg) {
		return "WARN"
	}
	return ""
}

// ---------- состояние служб и курсоры журнала ----------

func getSvc(unit string) *svcStat {
	svcMu.Lock()
	defer svcMu.Unlock()
	if s, ok := svcState[unit]; ok {
		cp := *s
		return &cp
	}
	return &svcStat{Unit: unit, LastRxSec: -1, Nums: map[string]uint64{}}
}

func putSvc(unit string, s *svcStat) {
	svcMu.Lock()
	defer svcMu.Unlock()
	cp := *s
	svcState[unit] = &cp
}

func svcSnapshot() []svcStat {
	svcMu.Lock()
	defer svcMu.Unlock()
	out := make([]svcStat, 0, len(unitList))
	for _, u := range unitList {
		if s, ok := svcState[u]; ok {
			out = append(out, *s)
			continue
		}
		out = append(out, svcStat{Unit: u, LastRxSec: -1})
	}
	return out
}

func getCursor(unit string) string {
	curMu.Lock()
	defer curMu.Unlock()
	return cursors[unit]
}

func setCursor(unit, c string) {
	curMu.Lock()
	defer curMu.Unlock()
	cursors[unit] = c
}
