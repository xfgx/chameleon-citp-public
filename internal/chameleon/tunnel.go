package chameleon

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

// Кодировка целевого адреса внутри туннеля — формат SOCKS5 ATYP:
//
//	0x01 || IPv4(4) || port(2)
//	0x03 || len(1) || domain || port(2)
//	0x04 || IPv6(16) || port(2)
//
// Первый кадр данных после рукопожатия — это адрес назначения.
// Сервер подключается к нему и отвечает кадром [0x00] (успех)
// или [0x01 || сообщение] (ошибка). Дальше — двунаправленный релей.

// EncodeTarget кодирует "host:port" в ATYP-формат.
func EncodeTarget(hostport string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("bad port %q", portStr)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))

	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return append(append([]byte{0x01}, v4...), pb[:]...), nil
		}
		return append(append([]byte{0x04}, ip.To16()...), pb[:]...), nil
	}
	if len(host) > 255 {
		return nil, fmt.Errorf("domain too long")
	}
	b := append([]byte{0x03, byte(len(host))}, host...)
	return append(b, pb[:]...), nil
}

// ParseTarget разбирает ATYP-формат обратно в "host:port".
func ParseTarget(b []byte) (string, error) {
	if len(b) < 4 {
		return "", fmt.Errorf("target too short")
	}
	var host string
	var portOff int
	switch b[0] {
	case 0x01:
		if len(b) < 7 {
			return "", fmt.Errorf("ipv4 target truncated")
		}
		host = net.IP(b[1:5]).String()
		portOff = 5
	case 0x03:
		l := int(b[1])
		if len(b) < 2+l+2 {
			return "", fmt.Errorf("domain target truncated")
		}
		host = string(b[2 : 2+l])
		portOff = 2 + l
	case 0x04:
		if len(b) < 19 {
			return "", fmt.Errorf("ipv6 target truncated")
		}
		host = net.IP(b[1:17]).String()
		portOff = 17
	default:
		return "", fmt.Errorf("unknown atyp 0x%02x", b[0])
	}
	if len(b) != portOff+2 {
		return "", fmt.Errorf("target has trailing data")
	}
	if host == "" {
		return "", fmt.Errorf("target host is empty")
	}
	port := binary.BigEndian.Uint16(b[portOff : portOff+2])
	if port == 0 {
		return "", fmt.Errorf("target port is zero")
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// Ответы сервера на запрос подключения.
var (
	TargetOK   = []byte{0x00}
	TargetFail = []byte{0x01}
)

// Relay гоняет данные между chameleon-соединением и обычным TCP до
// закрытия любой из сторон. Блокирует до завершения обоих направлений.
func Relay(cc *Conn, raw net.Conn) {
	done := make(chan struct{}, 2)

	go func() { // туннель → цель
		defer func() { done <- struct{}{} }()
		for {
			msg, err := cc.ReadMessage()
			if err != nil {
				break
			}
			if len(msg) == 0 { // FIN-кадр: удалённая сторона закрыла запись
				break
			}
			if _, err := raw.Write(msg); err != nil {
				break
			}
		}
		if tc, ok := raw.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	go func() { // цель → туннель
		defer func() { done <- struct{}{} }()
		buf := make([]byte, maxPayload)
		for {
			n, err := raw.Read(buf)
			if n > 0 {
				if werr := cc.WriteMessage(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				if err == io.EOF {
					// конец потока от цели — шлём пустой data-кадр как FIN
					cc.WriteMessage(nil)
				}
				break
			}
		}
	}()

	<-done
	<-done
}
