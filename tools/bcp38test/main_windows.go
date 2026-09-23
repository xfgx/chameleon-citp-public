//go:build windows

package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"
	"unsafe"
)

const receiverIP = "192.0.2.10"
const spoofedIP = "198.51.100.10"
const receiverPort = 39838
const checkURL = "http://192.0.2.10:39839/check?nonce="

type divertAddress struct {
	Timestamp int64
	Flags     uint32
	Reserved2 uint32
	Data      [64]byte
}
type result struct {
	Control int  `json:"control"`
	Spoof   int  `json:"spoof"`
	Seen    bool `json:"seen"`
	Count   int  `json:"count"`
}

var wd = syscall.NewLazyDLL("WinDivert.dll")
var procOpen = wd.NewProc("WinDivertOpen")
var procRecv = wd.NewProc("WinDivertRecv")
var procSend = wd.NewProc("WinDivertSend")
var procClose = wd.NewProc("WinDivertClose")

func main() {
	fmt.Println("Chameleon BCP38 path diagnostic v2 (safe fixed-node build)")
	fmt.Printf("Fixed path: this Windows host -> %s UDP/%d\n", receiverIP, receiverPort)
	fmt.Printf("Fixed spoofed source: %s; no CLI targets or traffic controls\n\n", spoofedIP)
	nonce := make([]byte, 16)
	if _, e := rand.Read(nonce); e != nil {
		fatal("random nonce", e)
	}
	n := hex.EncodeToString(nonce)
	if _, e := check(n); e != nil {
		fmt.Printf("STAGE 0 RECEIVER: FAIL (%v)\n", e)
		finish("INCONCLUSIVE: receiver/check endpoint is unreachable")
		return
	}
	fmt.Println("STAGE 0 RECEIVER: OK")
	control := []byte("CB38v2:C:" + n)
	dst := &net.UDPAddr{IP: net.ParseIP(receiverIP), Port: receiverPort}
	c, e := net.DialUDP("udp4", nil, dst)
	if e != nil {
		fatal("ordinary UDP socket", e)
	}
	for i := 0; i < 3; i++ {
		_, _ = c.Write(control)
		time.Sleep(120 * time.Millisecond)
	}
	local := c.LocalAddr().String()
	_ = c.Close()
	time.Sleep(500 * time.Millisecond)
	r1, e := check(n)
	if e != nil {
		fatal("control result check", e)
	}
	fmt.Printf("STAGE 1 NORMAL UDP: sent=3 received=%d local=%s\n", r1.Control, local)
	if e := wd.Load(); e != nil {
		fmt.Printf("STAGE 2 LOCAL INJECTION: FAIL (WinDivert.dll: %v)\n", e)
		finish("INCONCLUSIVE: fully extract the ZIP and run as Administrator")
		return
	}
	sf := []byte("outbound and ip.SrcAddr == 198.51.100.10 and ip.DstAddr == 192.0.2.10 and udp.DstPort == 39838\x00")
	sniff, _, we := procOpen.Call(uintptr(unsafe.Pointer(&sf[0])), 0, 0, 1|4)
	if sniff == ^uintptr(0) {
		fmt.Printf("STAGE 2 LOCAL INJECTION: FAIL (open sniffer: %v)\n", we)
		finish("INCONCLUSIVE: WinDivert driver did not open; run as Administrator")
		return
	}
	defer procClose.Call(sniff)
	sendf := []byte("false\x00")
	sender, _, we := procOpen.Call(uintptr(unsafe.Pointer(&sendf[0])), 0, 1000, 8)
	if sender == ^uintptr(0) {
		fmt.Printf("STAGE 2 LOCAL INJECTION: FAIL (open sender: %v)\n", we)
		finish("INCONCLUSIVE: WinDivert sender did not open; run as Administrator")
		return
	}
	defer procClose.Call(sender)
	observed := make(chan bool, 1)
	go func() {
		buf := make([]byte, 2048)
		var got uint32
		var a divertAddress
		ok, _, _ := procRecv.Call(sniff, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&got)), uintptr(unsafe.Pointer(&a)))
		observed <- ok != 0 && got > 0
	}()
	packet := ipv4UDP(net.ParseIP(spoofedIP).To4(), net.ParseIP(receiverIP).To4(), 39837, receiverPort, []byte("CB38v2:S:"+n))
	a := divertAddress{Flags: 1 << 17}
	sentOK := 0
	for i := 0; i < 8; i++ {
		var sent uint32
		ok, _, _ := procSend.Call(sender, uintptr(unsafe.Pointer(&packet[0])), uintptr(len(packet)), uintptr(unsafe.Pointer(&sent)), uintptr(unsafe.Pointer(&a)))
		if ok != 0 && int(sent) == len(packet) {
			sentOK++
		}
		time.Sleep(120 * time.Millisecond)
	}
	localSeen := false
	select {
	case localSeen = <-observed:
	case <-time.After(2 * time.Second):
	}
	procClose.Call(sniff)
	fmt.Printf("STAGE 2 LOCAL INJECTION: send_api=%d/8 observed_after_injection=%v\n", sentOK, localSeen)
	time.Sleep(800 * time.Millisecond)
	r2, e := check(n)
	if e != nil {
		fatal("spoof result check", e)
	}
	fmt.Printf("STAGE 3 REMOTE SPOOF: received=%d/8\n\n", r2.Spoof)
	switch {
	case r2.Spoof > 0:
		finish(fmt.Sprintf("BCP38 EGRESS FILTERING NOT OBSERVED (%d/8 reached the fixed receiver)", r2.Spoof))
	case r1.Control == 0:
		finish("INCONCLUSIVE: ordinary UDP did not reach the receiver on this network")
	case sentOK != 8 || !localSeen:
		finish("INCONCLUSIVE: local WinDivert injection was not independently observed")
	default:
		finish("ON-PATH SOURCE VALIDATION OBSERVED: normal UDP arrived, locally observed spoofed probes did not")
	}
}
func check(n string) (result, error) {
	var out result
	c := &http.Client{Timeout: 4 * time.Second}
	r, e := c.Get(checkURL + n)
	if e != nil {
		return out, e
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return out, fmt.Errorf("HTTP %s", r.Status)
	}
	e = json.NewDecoder(r.Body).Decode(&out)
	return out, e
}
func ipv4UDP(src, dst net.IP, sp, dp int, payload []byte) []byte {
	p := make([]byte, 28+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	binary.BigEndian.PutUint16(p[4:6], 0x3838)
	binary.BigEndian.PutUint16(p[6:8], 0x4000)
	p[8], p[9] = 64, 17
	copy(p[12:16], src)
	copy(p[16:20], dst)
	binary.BigEndian.PutUint16(p[10:12], checksum(p[:20]))
	binary.BigEndian.PutUint16(p[20:22], uint16(sp))
	binary.BigEndian.PutUint16(p[22:24], uint16(dp))
	binary.BigEndian.PutUint16(p[24:26], uint16(8+len(payload)))
	copy(p[28:], payload)
	return p
}
func checksum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 != 0 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = (s & 0xffff) + (s >> 16)
	}
	return ^uint16(s)
}
func fatal(stage string, e error) {
	fmt.Printf("\nRESULT: INCONCLUSIVE: %s: %v\n", stage, e)
	pause()
	os.Exit(1)
}
func finish(s string) { fmt.Println("RESULT: " + s); pause() }
func pause()          { fmt.Print("\nPress Enter to close..."); var x string; _, _ = fmt.Scanln(&x) }
