// probe4hit — пробник симметрии v4-ответа для «портового провода» (2026-09-04).
//
// Проверяет три факта, без которых схема «случайный исходный порт →
// случайный адрес ноды : случайный порт» не работает вообще:
//
//  1. Даёт ли dual-stack сокет ([::]:port) адрес НАЗНАЧЕНИЯ для IPv4-датаграмм
//     (IPV6_RECVPKTINFO → cm.Dst как ::ffff:a.b.c.d). Без этого нода не знает,
//     на КАКОЙ свой адрес пришёл пакет.
//  2. Можно ли ответить С ЭТОГО адреса (ControlMessage.Src с v4-mapped IP).
//  3. При активном nft redirect — увидит ли клиент ответ с ТОГО ЖЕ
//     адреса И порта, куда слал (conntrack обязан переписать src обратно).
//     Если нет — stateful-NAT роутера клиента отбросит ответы, и схема мертва.
//
// Локальные пакеты не проходят prerouting, поэтому режимы разделены:
// сервер и клиент запускаются в РАЗНЫХ netns через veth.
//
// Запуск:
//
//	probe4hit srv <listen-port> [секунд-жизни]
//	probe4hit cli <dst-ip> <dst-port>
package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"golang.org/x/net/ipv6"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("PROBE_USAGE probe4hit srv <listen-port> [sec] | probe4hit cli <dst-ip> <dst-port>")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "srv":
		port, err := strconv.Atoi(os.Args[2])
		if err != nil {
			fmt.Println("PROBE_BAD_PORT", os.Args[2])
			os.Exit(2)
		}
		sec := 30
		if len(os.Args) > 3 {
			if v, err := strconv.Atoi(os.Args[3]); err == nil {
				sec = v
			}
		}
		serve(port, sec)
	case "cli":
		if len(os.Args) < 4 {
			fmt.Println("PROBE_USAGE probe4hit cli <dst-ip> <dst-port>")
			os.Exit(2)
		}
		ip := net.ParseIP(os.Args[2])
		port, err := strconv.Atoi(os.Args[3])
		if ip == nil || err != nil {
			fmt.Println("PROBE_BAD_TARGET", os.Args[2], os.Args[3])
			os.Exit(2)
		}
		client(ip, port)
	default:
		fmt.Println("PROBE_BAD_MODE", os.Args[1])
		os.Exit(2)
	}
}

// serve — «нода»: один dual-stack сокет, как в ks-vpn; ответ с hit-адреса.
func serve(port, sec int) {
	srv, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		fmt.Println("SRV_LISTEN_ERR", err)
		os.Exit(1)
	}
	defer srv.Close()
	p := ipv6.NewPacketConn(srv)
	if err := p.SetControlMessage(ipv6.FlagDst, true); err != nil {
		fmt.Println("SRV_PKTINFO_ERR", err)
	} else {
		fmt.Println("SRV_PKTINFO_OK listen=" + strconv.Itoa(port))
	}
	deadline := time.Now().Add(time.Duration(sec) * time.Second)
	buf := make([]byte, 2048)
	for time.Now().Before(deadline) {
		srv.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, cm, src, err := p.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			fmt.Println("SRV_READ_ERR", err)
			return
		}
		hitStr := "<nil>"
		var hit net.IP
		if cm != nil && cm.Dst != nil {
			hit = cm.Dst
			hitStr = hit.String()
		}
		fmt.Printf("SRV_GOT n=%d from=%v cmDst=%s\n", n, src, hitStr)
		if hit == nil {
			fmt.Println("SRV_NO_HIT")
			p.WriteTo([]byte("pong"), nil, src)
			continue
		}
		if _, err := p.WriteTo([]byte("pong"), &ipv6.ControlMessage{Src: hit}, src); err != nil {
			fmt.Println("SRV_REPLY_HIT_ERR", err)
			if _, err := p.WriteTo([]byte("pong"), nil, src); err != nil {
				fmt.Println("SRV_REPLY_PLAIN_ERR", err)
			} else {
				fmt.Println("SRV_REPLY_PLAIN_OK")
			}
			continue
		}
		fmt.Println("SRV_REPLY_HIT_OK src=" + hitStr)
	}
	fmt.Println("SRV_DONE")
}

// client — сокет со СЛУЧАЙНЫМ свободным портом (ровно как пул wire4).
func client(dstIP net.IP, dstPort int) {
	cli, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 0})
	if err != nil {
		fmt.Println("CLI_LISTEN_ERR", err)
		os.Exit(1)
	}
	defer cli.Close()
	srcPort := cli.LocalAddr().(*net.UDPAddr).Port
	fmt.Printf("CLI_SEND src_port=%d -> %s:%d\n", srcPort, dstIP, dstPort)
	if _, err := cli.WriteToUDP([]byte("ping"), &net.UDPAddr{IP: dstIP, Port: dstPort}); err != nil {
		fmt.Println("CLI_SEND_ERR", err)
		os.Exit(1)
	}
	cli.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	n, from, err := cli.ReadFromUDP(buf)
	if err != nil {
		fmt.Println("CLI_NO_REPLY", err)
		return
	}
	verdict := "MISMATCH"
	if from.IP.Equal(dstIP) && from.Port == dstPort {
		verdict = "SYMMETRIC"
	}
	fmt.Printf("CLI_GOT n=%d from=%v %s (слал на %s:%d)\n", n, from, verdict, dstIP, dstPort)
}
