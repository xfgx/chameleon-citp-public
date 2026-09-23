package main

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"chameleon/internal/chameleon"
)

// SOCKS5-сервер на localhost: сюда система/браузер направляют трафик.
// Каждый входящий поток = отдельный сеанс "Хамелеон" к ноде
// (свежая маска на каждое соединение — ритм и сигнатуры не накапливаются).

func serveSOCKS(addr string, m *Manager) error {
	ln, actual, err := listenTCP(m, addr, "SOCKS5")
	if err != nil {
		return err
	}
	m.SetListenAddr("socks", actual)
	log.Printf("chamd: SOCKS5 слушает %s", actual)
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleSOCKS(c, m)
	}
}

func handleSOCKS(c net.Conn, m *Manager) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))

	// Greeting: VER NMETHODS METHODS...
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil || head[0] != 0x05 {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	noAuth := false
	for _, method := range methods {
		if method == 0x00 {
			noAuth = true
			break
		}
	}
	if !noAuth {
		_, _ = c.Write([]byte{0x05, 0xff})
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil { // no-auth
		return
	}

	// Request: VER CMD RSV ATYP ADDR PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil || req[0] != 0x05 {
		return
	}
	atyp := req[3]
	var host string
	switch atyp {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x03:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(c, lb); err != nil {
			return
		}
		b := make([]byte, int(lb[0]))
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = string(b)
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		writeSocksReply(c, 0x08)
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(pb))))
	c.SetDeadline(time.Time{})

	// UDP ASSOCIATE — датаграммы через туннель (DNS, QUIC, игры).
	if req[1] == 0x03 {
		serveUDPAssociate(c, m)
		return
	}
	if req[1] != 0x01 { // только CONNECT
		writeSocksReply(c, 0x07)
		return
	}
	st, err := m.openStream(target)
	if err != nil {
		m.logf("socks→%s: %v", target, err)
		writeSocksReply(c, 0x05)
		return
	}
	defer st.Close()
	m.logf("socks→%s: поток открыт", target)

	if err := writeSocksReply(c, 0x00); err != nil {
		return
	}

	// Двунаправленный релей: локальное соединение ↔ поток мультиплексора.
	done := make(chan struct{}, 2)
	go func() { // локальное → поток (исходящий трафик)
		n, _ := io.Copy(st, c)
		m.upBytes.Add(uint64(n))
		st.Close()
		done <- struct{}{}
	}()
	go func() { // поток → локальное (входящий трафик)
		n, _ := io.Copy(c, st)
		m.downBytes.Add(uint64(n))
		done <- struct{}{}
	}()
	<-done
	<-done
}

func writeSocksReply(c net.Conn, rep byte) error {
	// VER REP RSV ATYP=IPv4 0.0.0.0:0
	_, err := c.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

// serveUDPAssociate — SOCKS5 UDP ASSOCIATE поверх туннельного UDP-релея.
// Локальные/широковещательные датаграммы (NetBIOS, mDNS, SSDP) молча
// дропаются — им на ноде делать нечего, а tun2socks доволен уже тем,
// что ассоциация успешна.
func serveUDPAssociate(c net.Conn, m *Manager) {
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		writeSocksReply(c, 0x05)
		return
	}
	defer udp.Close()

	port := udp.LocalAddr().(*net.UDPAddr).Port
	reply := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, byte(port >> 8), byte(port)}
	if _, err := c.Write(reply); err != nil {
		return
	}

	// TCP-контрольное соединение живёт, пока жива ассоциация.
	quit := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, c)
		close(quit)
	}()

	type relay struct {
		st     *chameleon.Stream
		target string
	}
	relays := map[string]*relay{}
	defer func() {
		for _, r := range relays {
			r.st.Close()
		}
	}()

	var clientAddrMu sync.RWMutex
	var clientAddr *net.UDPAddr
	buf := make([]byte, 65535)
	for {
		select {
		case <-quit:
			return
		default:
		}
		udp.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, src, err := udp.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		clientAddrMu.Lock()
		clientAddr = src.(*net.UDPAddr)
		clientAddrMu.Unlock()
		d := buf[:n]
		if len(d) < 10 || d[0] != 0 || d[1] != 0 || d[2] != 0 {
			continue // не SOCKS5-UDP заголовок или фрагмент
		}
		host, off, ok := parseUDPDatagramTarget(d)
		if !ok {
			continue
		}
		target := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(d[off-2:off]))))
		if isJunkUDP(host) {
			continue // broadcast/multicast/локалка — дропаем молча
		}
		payload := append([]byte(nil), d[off:]...)

		r := relays[target]
		if r == nil {
			st, err := m.openUDPStream(target)
			if err != nil {
				m.logf("udp→%s: %v", target, err)
				continue
			}
			r = &relay{st: st, target: target}
			relays[target] = r
			m.logf("udp→%s: релей открыт", target)
			go func(r *relay) {
				rb := make([]byte, 2+65535)
				hdr := socksUDPHeader(r.target) // реальный источник — иначе tun2socks дропает
				for {
					if _, err := io.ReadFull(r.st, rb[:2]); err != nil {
						return
					}
					dn := int(binary.BigEndian.Uint16(rb[:2]))
					if _, err := io.ReadFull(r.st, rb[:dn]); err != nil {
						return
					}
					m.downBytes.Add(uint64(dn))
					clientAddrMu.RLock()
					dst := clientAddr
					clientAddrMu.RUnlock()
					if dst == nil {
						continue
					}
					out := append(append([]byte(nil), hdr...), rb[:dn]...)
					_, _ = udp.WriteTo(out, dst)
				}
			}(r)
		}
		frame := make([]byte, 2+len(payload))
		binary.BigEndian.PutUint16(frame[:2], uint16(len(payload)))
		copy(frame[2:], payload)
		if _, err := r.st.Write(frame); err != nil {
			r.st.Close()
			delete(relays, target)
		} else {
			m.upBytes.Add(uint64(len(payload)))
		}
	}
}

// parseUDPDatagramTarget вытаскивает хост и смещение payload из
// SOCKS5-UDP датаграммы: RSV(2) FRAG ATYP ADDR PORT DATA.
func parseUDPDatagramTarget(d []byte) (host string, off int, ok bool) {
	switch d[3] {
	case 0x01:
		if len(d) < 10 {
			return "", 0, false
		}
		return net.IP(d[4:8]).String(), 10, true
	case 0x03:
		l := int(d[4])
		if len(d) < 5+l+2 {
			return "", 0, false
		}
		return string(d[5 : 5+l]), 5 + l + 2, true
	case 0x04:
		if len(d) < 22 {
			return "", 0, false
		}
		return net.IP(d[4:20]).String(), 22, true
	}
	return "", 0, false
}

// isJunkUDP — широковещательный/мультикаст/локальный трафик,
// который не должен уезжать на ноду.
func isJunkUDP(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false // домен — пусть резолвит нода
	}
	if ip.IsMulticast() || ip.IsLoopback() || ip.IsUnspecified() {
		return true
	}
	if ip.Equal(net.ParseIP("255.255.255.255")) {
		return true
	}
	if ip.IsPrivate() {
		return true
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	// Бродкаст нашей TUN-подсети (10.66.0.255 и т.п.).
	if ip4 := ip.To4(); ip4 != nil && ip4[3] == 255 {
		return true
	}
	return false
}

// socksUDPHeader строит SOCKS5-UDP заголовок (RSV FRAG ATYP ADDR PORT)
// с РЕАЛЬНЫМ адресом источника. С 0.0.0.0:0 tun2socks считает ответы
// чужими ("symmetric NAT: drop packet") и DNS/QUIC/STUN молча умирают.
func socksUDPHeader(target string) []byte {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return []byte{0, 0, 0, 0x01, 0, 0, 0, 0, 0, 0}
	}
	port, _ := strconv.Atoi(portStr)
	h := []byte{0, 0, 0}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			h = append(h, 0x01, ip4[0], ip4[1], ip4[2], ip4[3])
		} else if ip16 := ip.To16(); ip16 != nil {
			h = append(h, 0x04)
			h = append(h, ip16...)
		}
	} else if len(host) < 256 {
		h = append(h, 0x03, byte(len(host)))
		h = append(h, []byte(host)...)
	} else {
		return []byte{0, 0, 0, 0x01, 0, 0, 0, 0, 0, 0}
	}
	return append(h, byte(port>>8), byte(port))
}
