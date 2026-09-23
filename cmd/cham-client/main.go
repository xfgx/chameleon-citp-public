package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"chameleon/internal/chameleon"
)

// cham-client — демонстрационный клиент: подключается, шлёт сообщение,
// печатает эхо-ответ.
//
// Несущий транспорт (-carrier):
//   - tcp  — классический TCP + аутентифицированное рукопожатие X25519 +
//     морфящие кадры (как раньше);
//   - ttls — CITP v3.0 Sub-Horizon TTL Smuggling: сообщение уходит одним
//     зашифрованным (AES-256-GCM, ключ из HKDF по PSK) UDP-кадром с
//     фиксированным IP TTL на TTLS-фронт ноды (cham-server -ttls-listen),
//     эхо читается тем же сокетом. TCP-соединение не создаётся вовсе.
func main() {
	connect := flag.String("connect", "127.0.0.1:9443", "адрес ноды (tcp: host:9443; ttls: host:55353)")
	pubkey := flag.String("pubkey", "", "публичный ключ ноды (base64), только для tcp")
	clientkey := flag.String("clientkey", "", "приватный ключ этого устройства (base64), только для tcp")
	msg := flag.String("msg", "privet iz chameleon", "сообщение для эха")
	carrier := flag.String("carrier", "tcp", "несущий транспорт: tcp | ttls")
	ttlsTTL := flag.Int("ttls-ttl", 64, "TTLS: исходящий IP TTL (64 = прямой обмен клиент<->нода; меньше = срыв за TAP-узлом)")
	ttlsSecret := flag.String("ttls-secret", "", "TTLS: общий с нодой секрет (PSK)")
	ttlsTimeout := flag.Duration("ttls-timeout", 10*time.Second, "TTLS: сколько ждать эхо-ответ")
	flag.Parse()

	switch *carrier {
	case "ttls":
		runTTLS(*connect, *ttlsSecret, *ttlsTTL, *msg, *ttlsTimeout)
	case "tcp":
		runTCP(*connect, *pubkey, *clientkey, *msg)
	default:
		log.Fatalf("неизвестный carrier %q: используйте tcp или ttls", *carrier)
	}
}

// runTCP — классический путь: TCP + рукопожатие + морфящий поток.
func runTCP(connect, pubkey, clientkey, msg string) {
	pub, err := chameleon.ParseNodePubKey(pubkey)
	if err != nil {
		log.Fatal(err)
	}
	ck, err := chameleon.ParseNodePrivKey(clientkey)
	if err != nil {
		log.Fatal(err)
	}
	c, err := net.DialTimeout("tcp", connect, 5*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	sess, err := chameleon.ClientHandshake(c, pub, ck)
	if err != nil {
		log.Fatalf("handshake: %v", err)
	}
	conn, err := chameleon.NewClientConn(c, sess)
	if err != nil {
		log.Fatal(err)
	}
	if err := conn.WriteMessage([]byte(msg)); err != nil {
		log.Fatal(err)
	}
	reply, err := conn.ReadMessage()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("эхо-ответ: %q\n", reply)
}

// runTTLS — путь CITP v3.0: фантомный UDP-кадр с заданным TTL на TTLS-фронт
// ноды; эхо приходит тем же каналом. Никакого TCP/TLS на проводе нет — для
// DPI это одиночные короткие UDP-датаграммы с белым шумом внутри.
func runTTLS(connect, secret string, ttl int, msg string, timeout time.Duration) {
	if secret == "" {
		log.Fatal("-carrier ttls требует -ttls-secret (PSK ноды)")
	}
	c := chameleon.NewTTLSCarrier(chameleon.TTLSConfig{Secret: secret, TTL: ttl})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Dial(ctx, connect); err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	if err := c.SendControl([]byte(msg)); err != nil {
		log.Fatal(err)
	}
	log.Printf("ttls: кадр ушёл на %s (TTL=%d, AES-256-GCM), жду эхо до %v...", connect, ttl, timeout)
	if err := c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		log.Fatal(err)
	}
	reply, err := c.Receive()
	if err != nil {
		log.Fatalf("ttls: эхо не получено: %v", err)
	}
	fmt.Printf("эхо-ответ (ttls через %s): %q\n", connect, reply)
}
