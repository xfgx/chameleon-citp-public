package chameleon

// wsconn.go — CDN-фронтинг: несущий транспорт WebSocket поверх TLS через
// фронт (Cloudflare Worker и т.п.). Для провайдера/DPI/ТСПУ destination IP
// соединения — это anycast-IP CDN, а не IP наших нод: ноды в трафике клиента
// не появляются вообще. Поверх WS-потока идёт обычное рукопожатие CITP и мux —
// протокол выше несущего слоя не меняется (принцип Carrier-абстракции).
//
// Реальный «IP spoofing» (подделка destination IP) для двустороннего трафика
// невозможен: обратные пакеты роутятся по destination IP, а исходный спуфинг
// режется BCP38-фильтрами на входе в сеть провайдера. Фронтинг — это тот же
// эффект легальным путём: физическое соединение действительно идёт к CDN,
// а CDN (наш воркер) ретранслирует байты на ноду.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// wsConn адаптирует WebSocket к net.Conn: бинарные сообщения как непрерывный
// байтовый поток (mux-кадры пишутся по одному сообщению на Write).
type wsConn struct {
	ws     *websocket.Conn
	r      io.Reader // текущее недочитанное сообщение
	wmu    sync.Mutex
	closed chan struct{}
	once   sync.Once
}

func newWSConn(ws *websocket.Conn) *wsConn {
	ws.SetReadLimit(4 << 20)
	return &wsConn{ws: ws, closed: make(chan struct{})}
}

func (c *wsConn) Read(p []byte) (int, error) {
	for {
		if c.r != nil {
			n, err := c.r.Read(p)
			if err == io.EOF {
				c.r = nil
				if n > 0 {
					return n, nil
				}
				continue
			}
			return n, err
		}
		mt, r, err := c.ws.NextReader()
		if err != nil {
			return 0, err
		}
		if mt != websocket.BinaryMessage {
			continue // ping/pong/text не несут данных канала
		}
		c.r = r
	}
}

func (c *wsConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	w, err := c.ws.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return 0, err
	}
	n, werr := w.Write(p)
	cerr := w.Close()
	if werr != nil {
		return n, werr
	}
	if cerr != nil {
		return n, cerr
	}
	return n, nil
}

func (c *wsConn) Close() error {
	var err error
	c.once.Do(func() {
		close(c.closed)
		_ = c.ws.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(2*time.Second))
		err = c.ws.Close()
	})
	return err
}

func (c *wsConn) LocalAddr() net.Addr                { return c.ws.LocalAddr() }
func (c *wsConn) RemoteAddr() net.Addr               { return c.ws.RemoteAddr() }
func (c *wsConn) SetDeadline(t time.Time) error      { _ = c.SetReadDeadline(t); return c.SetWriteDeadline(t) }
func (c *wsConn) SetReadDeadline(t time.Time) error  { return c.ws.SetReadDeadline(t) }
func (c *wsConn) SetWriteDeadline(t time.Time) error { return c.ws.SetWriteDeadline(t) }

// DialWS открывает WebSocket к фронту (wss://worker.example/b/<token>) и
// возвращает его как net.Conn. tlsConf — nil = системные корни; ServerName
// берётся из URL. dialPinIP, если непуст, — IP, к которому физически
// дозваниваемся вместо DNS-резолва хоста (DoH-пин автопилота при перехвате
// DNS провайдером): SNI/Host остаются исходными, идёт только сетевой путь.
func DialWS(ctx context.Context, wsURL, dialPinIP string, tlsConf *tls.Config) (net.Conn, error) {
	u, err := url.Parse(wsURL)
	if err != nil {
		return nil, fmt.Errorf("front url: %w", err)
	}
	if u.Scheme != "wss" && u.Scheme != "ws" {
		return nil, fmt.Errorf("front url: схема должна быть ws/wss, не %q", u.Scheme)
	}
	d := websocket.Dialer{
		HandshakeTimeout: 20 * time.Second,
		TLSClientConfig:  tlsConf,
		ReadBufferSize:   1 << 16,
		WriteBufferSize:  1 << 16,
	}
	if dialPinIP != "" {
		host := u.Hostname()
		port := u.Port()
		if port == "" {
			if u.Scheme == "wss" {
				port = "443"
			} else {
				port = "80"
			}
		}
		pinned := net.JoinHostPort(dialPinIP, port)
		d.NetDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			var nd net.Dialer
			return nd.DialContext(ctx, "tcp", pinned)
		}
		_ = host // SNI/Host остаются от URL — CDN маршрутизирует по имени
	}
	ws, resp, err := d.DialContext(ctx, u.String(), http.Header{"User-Agent": {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"}})
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("front ws: http %d: %w", resp.StatusCode, err)
		}
		return nil, fmt.Errorf("front ws: %w", err)
	}
	return newWSConn(ws), nil
}

// WSPathToken извлекает токен из пути вида /b/<token>.
func WSPathToken(path string) string {
	const pfx = "/b/"
	if len(path) > len(pfx) && path[:len(pfx)] == pfx {
		return path[len(pfx):]
	}
	return ""
}

var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  1 << 16,
	WriteBufferSize: 1 << 16,
	CheckOrigin:     func(*http.Request) bool { return true }, // origin не имеет смысла для не-браузерных клиентов
}

// AcceptWS поднимает входящий WS-запрос до net.Conn. Ведёт себя как обычный
// веб-сервер: на не-WS запросы отвечает 404 (маскировка под пустой сайт),
// на неверный токен — тоже 404 (активный зонд не отличит нас от веб-сервера).
func AcceptWS(w http.ResponseWriter, r *http.Request, wantToken string) (net.Conn, error) {
	if wantToken == "" || WSPathToken(r.URL.Path) != wantToken || !websocket.IsWebSocketUpgrade(r) {
		http.NotFound(w, r)
		return nil, errors.New("ws: отказ (нет токена/upgrade)")
	}
	ws, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return nil, err
	}
	return newWSConn(ws), nil
}
