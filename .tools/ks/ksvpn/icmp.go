package main

// icmp.go — минимальный IPv4 ICMP echo для keepalive-пинга ноды сквозь туннель.
// Клиент шлёт echo request на туннельный адрес ноды каждые 15 с: держит
// NAT-дыру открытой и даёт индикатор канала (lastRx в строке стадий).
// Ответы перехватываются в net→tun пути и в TUN не пишутся.

import (
	"encoding/binary"
	"net"
)

// kaID — идентификатор echo keepalive ("KS"), чтобы узнавать свои ответы.
const kaID uint16 = 0x4B53

// icmpEcho — IPv4-пакет ICMP echo request src→dst (без нагрузки).
func icmpEcho(src, dst net.IP, id, seq uint16) []byte {
	p := make([]byte, 20+8)
	p[0] = 0x45 // IPv4, IHL=5
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	p[8] = 64 // TTL
	p[9] = 1  // протокол ICMP
	copy(p[12:16], src.To4())
	copy(p[16:20], dst.To4())
	binary.BigEndian.PutUint16(p[10:], ipChecksum(p[:20]))
	o := 20
	p[o] = 8 // echo request
	binary.BigEndian.PutUint16(p[o+4:], id)
	binary.BigEndian.PutUint16(p[o+6:], seq)
	binary.BigEndian.PutUint16(p[o+2:], ipChecksum(p[o:]))
	return p
}

// isKaReply — это ответ на наш keepalive? (ICMP echo reply с kaID на наш tunIP)
func isKaReply(plain []byte, own net.IP) bool {
	if len(plain) < 28 || plain[0]>>4 != 4 || plain[9] != 1 {
		return false
	}
	o := int(plain[0]&0x0f) * 4 // IHL
	if len(plain) < o+8 {
		return false
	}
	return plain[o] == 0 && // echo reply
		binary.BigEndian.Uint16(plain[o+4:]) == kaID &&
		net.IP(plain[16:20]).Equal(own)
}

// ipChecksum — стандартная 16-битная контрольная сумма IP/ICMP.
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
