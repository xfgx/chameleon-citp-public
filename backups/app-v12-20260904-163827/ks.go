package mobilecore

// ks.go — Android data-plane на keystream-инверсии (тот же протокол, что cmd/ks-vpn).
// gomobile экспортирует StartKS / Mode / LastRxSec.

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"chameleon/internal/chaossync"
)

const (
	ksKaID     uint16 = 0x4B53
	ksEpochSec uint64 = 8
)

var (
	ksMu     sync.Mutex
	ksRun    bool
	ksCancel context.CancelFunc
	ksTun    int
	ksLastRx atomic.Int64
	modeName atomic.Value // string: "", "citp", "ks"
)

func init() {
	modeName.Store("")
}

// Mode — текущий data-plane: "citp", "ks" или пусто.
func Mode() string {
	v, _ := modeName.Load().(string)
	return v
}

// LastRxSec — возраст последней валидной KS-датаграммы; -1 если не было.
func LastRxSec() int64 {
	t := ksLastRx.Load()
	if t == 0 {
		return -1
	}
	return time.Now().Unix() - t
}

// StartKS поднимает KS-туннель на tunFd к peer (host:port) с master-ключом base64.
func StartKS(peer, masterB64 string, tunFd int32, p Protector) (errStr string) {
	defer func() {
		if r := recover(); r != nil {
			errStr = fmt.Sprintf("внутренний сбой KS: %v", r)
			logf("ПАНИКА KS: %v", r)
		}
	}()

	host, portStr, err := net.SplitHostPort(strings.TrimSpace(peer))
	if err != nil {
		return fmt.Sprintf("адрес KS: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 {
		return "порт KS некорректен"
	}
	master, err := chaossync.ParseMasterKey(masterB64)
	if err != nil {
		return err.Error()
	}
	peerIP := net.ParseIP(host).To4()
	if peerIP == nil {
		ips, err := net.LookupIP(host)
		if err != nil {
			return fmt.Sprintf("резолв %s: %v", host, err)
		}
		for _, ip := range ips {
			if ip4 := ip.To4(); ip4 != nil {
				peerIP = ip4
				break
			}
		}
	}
	if peerIP == nil {
		return "нужен IPv4 адрес ноды KS"
	}

	mu.Lock()
	if running || ksRun {
		mu.Unlock()
		return "уже запущено"
	}
	running = true
	ksRun = true
	modeName.Store("ks")
	ctx, cancel = context.WithCancel(context.Background())
	protector = p
	upBytes.Store(0)
	downBytes.Store(0)
	ksLastRx.Store(0)
	ksTun = int(tunFd)
	ksCancel = cancel
	localCtx := ctx
	mu.Unlock()

	fail := func(e error) string {
		stopKS()
		logf("ошибка запуска KS: %v", e)
		return e.Error()
	}

	sock, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		return fail(fmt.Errorf("udp: %w", err))
	}
	if f, err := sock.File(); err == nil {
		protectControl(f.Fd())
		_ = f.Close()
	} else {
		logf("KS: не смог protect UDP: %v", err)
	}

	dst := &net.UDPAddr{IP: peerIP, Port: port}
	tx := chaossync.NewRotatingSender(master, "c2n", ksEpochSec, time.Now())
	rx := chaossync.NewRotatingReceiver(master, "n2c", ksEpochSec, time.Now())
	ownTun := net.IPv4(10, 99, 1, 1)
	peerTun := net.IPv4(10, 99, 1, 2)

	logf("KS: туннель к %s:%d, TUN fd=%d", peerIP, port, tunFd)

	go func() {
		tk := time.NewTicker(15 * time.Second)
		defer tk.Stop()
		var seq uint16
		for {
			select {
			case <-localCtx.Done():
				return
			case <-tk.C:
				seq++
				tx.TickEpoch(time.Now())
				wire := tx.Seal(icmpEcho(ownTun, peerTun, ksKaID, seq))
				if _, err := sock.WriteToUDP(wire, dst); err == nil {
					cSentKS.Add(1)
				}
			}
		}
	}()

	go func() {
		buf := make([]byte, 2048)
		for {
			select {
			case <-localCtx.Done():
				return
			default:
			}
			_ = sock.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, _, err := sock.ReadFromUDP(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				select {
				case <-localCtx.Done():
					return
				default:
					logf("KS udp read: %v", err)
					return
				}
			}
			rx.TickEpoch(time.Now())
			plain, ok := rx.Ingest(append([]byte(nil), buf[:n]...))
			if !ok {
				continue
			}
			ksLastRx.Store(time.Now().Unix())
			if isKaReply(plain, ownTun) {
				continue
			}
			downBytes.Add(int64(len(plain)))
			if _, err := syscall.Write(int(tunFd), plain); err != nil {
				select {
				case <-localCtx.Done():
					return
				default:
				}
			}
		}
	}()

	go func() {
		buf := make([]byte, 2048)
		for {
			select {
			case <-localCtx.Done():
				_ = sock.Close()
				return
			default:
			}
			n, err := syscall.Read(int(tunFd), buf)
			if err != nil {
				select {
				case <-localCtx.Done():
					_ = sock.Close()
					return
				default:
					time.Sleep(20 * time.Millisecond)
					continue
				}
			}
			if n < 20 {
				continue
			}
			// петлестоп: dst = проводной IP ноды не в туннель
			if buf[0]>>4 == 4 && net.IP(buf[16:20]).Equal(peerIP) {
				continue
			}
			tx.TickEpoch(time.Now())
			wire := tx.Seal(buf[:n])
			if _, err := sock.WriteToUDP(wire, dst); err == nil {
				upBytes.Add(int64(n))
				cSentKS.Add(1)
			}
		}
	}()

	logf("KS: стек поднят, peer %s", dst.String())
	return ""
}

var cSentKS atomic.Uint64

func stopKS() {
	ksMu.Lock()
	defer ksMu.Unlock()
	mu.Lock()
	ksRun = false
	if modeName.Load() == "ks" {
		running = false
		modeName.Store("")
	}
	if ksCancel != nil {
		ksCancel()
		ksCancel = nil
	}
	mu.Unlock()
}

func icmpEcho(src, dst net.IP, id, seq uint16) []byte {
	p := make([]byte, 28)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	p[8] = 64
	p[9] = 1
	copy(p[12:16], src.To4())
	copy(p[16:20], dst.To4())
	binary.BigEndian.PutUint16(p[10:], ipChecksum(p[:20]))
	p[20] = 8
	binary.BigEndian.PutUint16(p[24:], id)
	binary.BigEndian.PutUint16(p[26:], seq)
	binary.BigEndian.PutUint16(p[22:], ipChecksum(p[20:]))
	return p
}

func isKaReply(plain []byte, own net.IP) bool {
	if len(plain) < 28 || plain[0]>>4 != 4 || plain[9] != 1 {
		return false
	}
	o := int(plain[0]&0x0f) * 4
	if len(plain) < o+8 {
		return false
	}
	return plain[o] == 0 &&
		binary.BigEndian.Uint16(plain[o+4:]) == ksKaID &&
		net.IP(plain[16:20]).Equal(own)
}

func ipChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
