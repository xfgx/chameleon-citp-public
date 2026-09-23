package chameleon

import (
	"fmt"
	"math/rand/v2"
	"net"
	"strings"
	"syscall"
	"time"
)

// Node — сервер-нода из пула.
type Node struct {
	Name   string `json:"name"`
	Addr   string `json:"addr"`   // host:port
	PubKey string `json:"pubkey"` // публичный ключ ноды (base64), обязателен с v2
}

// DialPool перебирает ноды в случайном порядке, пока одна не ответит
// валидным рукопожатием. Возвращает готовое соединение и адрес ноды.
// Если одна нода заблокирована по IP — трафик уйдёт через другую.
func DialPool(nodes []Node, clientPrivB64 string, timeout time.Duration) (*Conn, string, error) {
	if len(nodes) == 0 {
		return nil, "", fmt.Errorf("пул нод пуст")
	}
	shuffled := append([]Node{}, nodes...)
	rand.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})
	var errs []string
	for _, n := range shuffled {
		conn, err := DialNode(n.Addr, n.PubKey, clientPrivB64, timeout)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", n.Addr, err))
			continue
		}
		return conn, n.Addr, nil
	}
	return nil, "", fmt.Errorf("все ноды недоступны: %s", strings.Join(errs, "; "))
}

// DialNode подключается к одной ноде и выполняет аутентифицированное
// рукопожатие v2.1 (нужны публичный ключ ноды и ключ этого устройства).
func DialNode(addr, pubKeyB64, clientPrivB64 string, timeout time.Duration) (*Conn, error) {
	return DialNodeHook(addr, pubKeyB64, clientPrivB64, timeout, nil)
}

// DialNodeHook — как DialNode, но с хуком на сырой fd сокета ДО connect.
// На Android это VpnService.protect(fd): без защиты трафик туннеля к ноде
// ушёл бы обратно в VPN-интерфейс — петля.
func DialNodeHook(addr, pubKeyB64, clientPrivB64 string, timeout time.Duration, control func(fd uintptr)) (*Conn, error) {
	pub, err := ParseNodePubKey(pubKeyB64)
	if err != nil {
		return nil, fmt.Errorf("нода %s: %w", addr, err)
	}
	clientPriv, err := ParseNodePrivKey(clientPrivB64)
	if err != nil {
		return nil, fmt.Errorf("ключ клиента: %w", err)
	}
	d := &net.Dialer{Timeout: timeout}
	if control != nil {
		d.Control = func(network, address string, c syscall.RawConn) error {
			return c.Control(control)
		}
	}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	sess, err := ClientHandshake(c, pub, clientPriv)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}
	return NewClientConn(c, sess)
}
