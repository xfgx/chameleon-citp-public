package main

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"time"
)

// Локальный DNS-резолвер для TUN-режима.
// Windows шлёт UDP-запросы на 127.0.0.1:53; каждый запрос уходит через
// туннель как DNS-over-TCP к 8.8.8.8:53 — провайдер DNS не видит,
// снаружи резолв делает нода.
const (
	dnsUpstream    = "8.8.8.8:53"
	dnsReadTimeout = 4 * time.Second
	dnsMaxResponse = 4096
)

func serveDNS(m *Manager, addr string) {
	pc, actual, err := listenUDP(m, addr, "DNS")
	if err != nil {
		log.Printf("dns: %v (TUN-резолв не заведётся)", err)
		return
	}
	m.SetListenAddr("dns", actual)
	if actual != addr {
		log.Printf("dns: ВНИМАНИЕ: %s занят, резолвер на %s; TUN-режим ожидает 127.0.0.1:53", addr, actual)
	}
	log.Printf("chamd: DNS-резолвер на %s → %s через туннель", actual, dnsUpstream)
	buf := make([]byte, 4096)
	for {
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		query := append([]byte(nil), buf[:n]...)
		go handleDNS(pc, src, query, m)
	}
}

func handleDNS(pc net.PacketConn, src net.Addr, query []byte, m *Manager) {
	st, err := m.openStream(dnsUpstream)
	if err != nil {
		return // без активного подключения — молчим, система возьмёт другой DNS
	}
	defer st.Close()

	// DNS-over-TCP: 2-байтовый префикс длины.
	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame, uint16(len(query)))
	copy(frame[2:], query)
	if _, err := st.Write(frame); err != nil {
		return
	}

	// Канал с дедлайном для безопасного неблокирующего чтения ответа (FIND-08)
	type dnsResult struct {
		data []byte
		err  error
	}
	resCh := make(chan dnsResult, 1)

	go func() {
		header := make([]byte, 2)
		if _, err := io.ReadFull(st, header); err != nil {
			resCh <- dnsResult{nil, err}
			return
		}
		ln := int(binary.BigEndian.Uint16(header))
		if ln <= 0 || ln > dnsMaxResponse {
			resCh <- dnsResult{nil, io.ErrUnexpectedEOF}
			return
		}
		ans := make([]byte, ln)
		if _, err := io.ReadFull(st, ans); err != nil {
			resCh <- dnsResult{nil, err}
			return
		}
		resCh <- dnsResult{ans, nil}
	}()

	select {
	case res := <-resCh:
		if res.err == nil && len(res.data) > 0 {
			pc.WriteTo(res.data, src)
		}
	case <-time.After(dnsReadTimeout):
		// Таймаут получения DNS-ответа — st.Close() в defer завершит зависшую горутину
		return
	}
}
