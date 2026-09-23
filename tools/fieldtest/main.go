// Command fieldtest — живой полевой прогон Control Fabric против ноды через
// реальный интернет: аутентифицированное рукопожатие с нодой (триггерит
// публикацию управляющего hint во все каналы), затем чтение bulletin (HTTPS),
// DNS-маячка (UDP) и CAR-кадра (HTTP через кодовую книгу) обратно по сети.
//
// Это проверка этапа B4 из документации: каналы работают не на loopback, а
// поверх реального интернет-пути. Вердиктную часть ТСПУ здесь заменяет
// прямое чтение (бит 1 = токен в теле ответа); настоящая ТСПУ проверяется
// с клиентской сети владельца.
//
// Этап F: чтение идёт с привязкой к эпохе и смещением окна кодовой книги —
// фабрика собирается с WithSchedule (каноническая модель v1), как у ноды
// с -cf-schedule=true (дефолт).
package main

import (
	"context"
	"crypto/ecdh"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"chameleon/internal/chameleon"
)

// doChainCheck открывает внешний IP-echo через ноду в режиме каскада и
// печатает выходной IP: при рабочей цепочке это IP выходной (зарубежной)
// ноды, а не входной.
func doChainCheck(cc net.Conn, sess *chameleon.Session) {
	fmt.Println("[chain] открываю api.ipify.org:80 через ноду ...")
	conn, err := chameleon.NewClientConn(cc, sess)
	if err != nil {
		fmt.Printf("    chain FAIL: %v\n", err)
		return
	}
	mx := chameleon.NewMuxClient(conn)
	st, err := mx.Open("api.ipify.org:80")
	if err != nil {
		fmt.Printf("    chain OPEN FAIL: %v\n", err)
		return
	}
	defer st.Close()
	if _, err := fmt.Fprintf(st, "GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\nUser-Agent: curl/8.0\r\n\r\n"); err != nil {
		fmt.Printf("    chain WRITE FAIL: %v\n", err)
		return
	}
	type res struct {
		b   []byte
		err error
	}
	done := make(chan res, 1)
	go func() {
		b, err := io.ReadAll(st)
		done <- res{b, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			fmt.Printf("    chain READ FAIL: %v\n", r.err)
			return
		}
		fmt.Printf("    chain OK, ответ через каскад:\n%s\n", string(r.b))
	case <-time.After(25 * time.Second):
		fmt.Println("    chain READ TIMEOUT")
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "FATAL:", err)
		os.Exit(1)
	}
}

func main() {
	addr := flag.String("addr", "", "VPN-адрес ноды host:port")
	pubB64 := flag.String("pubkey", "", "публичный ключ ноды (base64)")
	cfSeed := flag.String("cf-seed", "", "общий seed Control Fabric")
	node := flag.String("node", "", "IP/хост ноды для control-каналов")
	dnsPort := flag.Int("dns-port", 53, "UDP-порт DNS-маячка (53 — стандартный, после делегации зоны)")
	skipCAR := flag.Bool("skip-car", false, "пропустить медленное чтение CAR-кадра")
	chainCheck := flag.Bool("chaincheck", false, "проверка каскада: открыть внешний IP-echo через ноду и показать выходной IP")
	clientKeyFile := flag.String("clientkey", "", "файл клиентского ключа (обязателен, если на ноде включён -allowfile); пустой = эфемерный ключ")
	flag.Parse()
	if *addr == "" || *pubB64 == "" || *cfSeed == "" || *node == "" {
		fmt.Println("нужны -addr, -pubkey, -cf-seed, -node")
		os.Exit(2)
	}

	pub, err := chameleon.ParseNodePubKey(*pubB64)
	must(err)
	var clientKey *ecdh.PrivateKey
	if *clientKeyFile != "" {
		b, err := os.ReadFile(*clientKeyFile)
		must(err)
		clientKey, err = chameleon.ParseNodePrivKey(strings.TrimSpace(string(b)))
		must(err)
		fmt.Println("    клиентский ключ: из файла (allowlist-режим)")
	} else {
		privB64, _, err := chameleon.GenerateNodeKey()
		must(err)
		clientKey, err = chameleon.ParseNodePrivKey(privB64)
		must(err)
		fmt.Println("    клиентский ключ: эфемерный (нода без allowlist)")
	}

	fmt.Printf("[1] handshake %s ...\n", *addr)
	cc, err := net.DialTimeout("tcp", *addr, 15*time.Second)
	must(err)
	start := time.Now()
	sess, err := chameleon.ClientHandshake(cc, pub, clientKey)
	must(err)
	fmt.Printf("    handshake OK за %v\n", time.Since(start))
	if *chainCheck {
		doChainCheck(cc, sess)
	}
	_ = cc.Close()

	sid := chameleon.ControlSessionID(clientKey.PublicKey().Bytes())
	fmt.Printf("    sessionID=%s\n", sid)
	time.Sleep(2 * time.Second) // даём публикации осесть по каналам

	ctx := context.Background()
	cf := chameleon.NewControlFabric([]byte("chameleon-control-fabric:"+*cfSeed), nil, nil, nil, nil).
		WithSchedule(nil, 0)
	if sched := cf.CurrentSchedule(time.Now()); sched != nil {
		fmt.Printf("    этап F: эпоха %d, порядок каналов %v, смещение CAR-окна %d\n",
			sched.Epoch, sched.ChannelOrder, sched.CARWindowOffset)
	}

	fmt.Printf("[2] bulletin https://%s:9444 ...\n", *node)
	cli := chameleon.NewCDNCacheStateClient("https://" + *node + ":9444").WithInsecureTLS()
	if msg, err := cf.RecoverControl(ctx, sid, cli); err != nil {
		fmt.Printf("    BOARD FAIL: %v\n", err)
	} else {
		fmt.Printf("    board OK: %s\n", msg)
	}

	fmt.Printf("[3] dns beacon %s:%d ...\n", *node, *dnsPort)
	dnsR := chameleon.NewDNSBeaconReader(*node, *dnsPort, "cf.chameleon.node", "c")
	if beacon, err := dnsR.ReadChunk(0); err != nil {
		fmt.Printf("    DNS FAIL: %v\n", err)
	} else {
		fmt.Printf("    dns OK: %s\n", beacon)
	}

	if *skipCAR {
		fmt.Println("[4] CAR пропущен по флагу")
		return
	}
	fmt.Printf("[4] car frame http://%s:9445 (тысячи окон, минуты) ...\n", *node)
	carR := chameleon.NewCARReader("http://" + *node + ":9445").
		WithPacer(chameleon.NewCARPacer(2*time.Millisecond, 0.3))
	start = time.Now()
	msg, err := cf.ReadControlCAR(carR, 2)
	if err != nil {
		fmt.Printf("    CAR FAIL: %v\n", err)
		return
	}
	fmt.Printf("    car OK за %v: %s\n", time.Since(start), msg)
}
