// Command probe — живой зонд ноды через реальный интернет: рукопожатие с
// заданным клиентским ключом + проверка поддержки RESOLVE (новая сборка с
// DNS-binding) с окном 4с. Используется для диагностики вышестоящей ноды
// каскада (белый список, версия протокола).
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"chameleon/internal/chameleon"
)

func main() {
	addr := flag.String("addr", "198.51.100.10:8443", "адрес ноды")
	wsURL := flag.String("ws", "", "CDN-фронтинг: WebSocket URL фронта (ws://host:port/b/<token> или wss://worker/...); задан — дозвон через фронт вместо прямого TCP")
	pubB64 := flag.String("pubkey", "hCs_ISiKS_DPbsA3mD2xhcHaIDa9d1G_AbYGBkBlAnc", "публичный ключ ноды")
	keyFile := flag.String("clientkey", "bin/data/client.key", "файл клиентского ключа (base64)")
	flag.Parse()

	pub, err := chameleon.ParseNodePubKey(*pubB64)
	if err != nil {
		fmt.Println("pubkey:", err)
		return
	}
	keyB64 := strings.TrimSpace(os.Getenv("CLIENTKEY"))
	if keyB64 == "" {
		b, err := os.ReadFile(*keyFile)
		if err != nil {
			fmt.Println("нет файла ключа:", err)
			return
		}
		keyB64 = strings.TrimSpace(string(b))
	}
	ck, err := chameleon.ParseNodePrivKey(keyB64)
	if err != nil {
		fmt.Println("clientkey:", err)
		return
	}

	var cc net.Conn
	if *wsURL != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		cc, err = chameleon.DialWS(ctx, *wsURL, "", nil)
		cancel()
	} else {
		cc, err = net.DialTimeout("tcp", *addr, 10*time.Second)
	}
	if err != nil {
		fmt.Println("dial:", err)
		return
	}
	defer cc.Close()
	t0 := time.Now()
	sess, err := chameleon.ClientHandshake(cc, pub, ck)
	if err != nil {
		fmt.Println("handshake FAIL:", err)
		return
	}
	fmt.Println("handshake OK за", time.Since(t0))
	conn, err := chameleon.NewClientConn(cc, sess)
	if err != nil {
		fmt.Println("conn:", err)
		return
	}
	mx := chameleon.NewMuxClient(conn)
	done := make(chan string, 1)
	go func() { _, err := mx.Resolve("google.com"); done <- fmt.Sprintf("%v", err) }()
	select {
	case s := <-done:
		fmt.Println("RESOLVE поддерживается (новая сборка):", s)
	case <-time.After(4 * time.Second):
		fmt.Println("RESOLVE молчит 4с -> СТАРАЯ сборка (legacy open)")
	}
}
