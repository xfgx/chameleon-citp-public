package chameleon

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// Кодирование/декодирование ResolutionObject — round-trip.
func TestResolutionRoundTrip(t *testing.T) {
	ro := &ResolutionObject{
		Domain: "example.com",
		Addrs:  []string{"93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"},
		Expiry: time.Now().Add(time.Minute).Unix(),
	}
	ro.Sign([]byte("seed"))
	got, err := DecodeResolutionObject(ro.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got.Domain != ro.Domain || len(got.Addrs) != 2 || got.Expiry != ro.Expiry {
		t.Fatalf("round-trip исказил объект: %+v", got)
	}
	if err := got.Verify([]byte("seed")); err != nil {
		t.Fatalf("свежий объект не прошёл Verify: %v", err)
	}
}

// Подделка подписи, чужой seed и истёкший TTL должны отвергаться.
func TestResolutionVerifyNegative(t *testing.T) {
	mk := func() *ResolutionObject {
		ro := &ResolutionObject{Domain: "a.ru", Addrs: []string{"1.2.3.4"}, Expiry: time.Now().Add(time.Minute).Unix()}
		ro.Sign([]byte("seed"))
		return ro
	}

	// Подмена адреса после подписи.
	ro := mk()
	ro.Addrs[0] = "6.6.6.6"
	if err := ro.Verify([]byte("seed")); err == nil {
		t.Fatal("подмена адреса не замечена")
	}
	// Чужой seed (чужой сеанс).
	if err := mk().Verify([]byte("other-seed")); err == nil {
		t.Fatal("объект из чужого сеанса принят")
	}
	// Просроченный объект.
	ro = mk()
	ro.Expiry = time.Now().Add(-time.Minute).Unix()
	ro.Sign([]byte("seed")) // подпись честная, но TTL истёк
	if err := ro.Verify([]byte("seed")); err == nil {
		t.Fatal("просроченный объект принят")
	}
}

// MatchHost: домен и его IP разрешены, чужой адрес — нет.
func TestResolutionMatch(t *testing.T) {
	ro := &ResolutionObject{Domain: "a.ru", Addrs: []string{"1.2.3.4"}}
	if !ro.MatchHost("a.ru") || !ro.MatchHost("1.2.3.4") || !ro.MatchAddr("1.2.3.4:443") {
		t.Fatal("свои адреса не совпали")
	}
	if ro.MatchHost("9.9.9.9") || ro.MatchAddr("9.9.9.9:443") || ro.MatchHost("b.ru") {
		t.Fatal("чужой адрес/домен принят")
	}
}

// FIND-06: Проверка ограничения количества адресов в ResolutionObject.
func TestResolutionAddressLimits(t *testing.T) {
	// 1. Попытка декодировать объект с na > maxResolvedAddresses (например, 100)
	buf := make([]byte, 0, 1000)
	buf = append(buf, 4) // domain len
	buf = append(buf, []byte("a.ru")...)
	buf = append(buf, 100) // na = 100 (> maxResolvedAddresses = 64)
	for i := 0; i < 100; i++ {
		buf = append(buf, 7)
		buf = append(buf, []byte("1.2.3.4")...)
	}
	var tmp [8]byte
	buf = append(buf, tmp[:]...)
	buf = append(buf, make([]byte, 32)...)

	_, err := DecodeResolutionObject(buf)
	if err == nil {
		t.Fatal("декодер должен отклонять na > maxResolvedAddresses")
	}

	// 2. Объект с na=10, но буфер урезан (атака через declared na без байт)
	shortBuf := []byte{4, 'a', '.', 'r', 'u', 10, 1, 'a'}
	_, err = DecodeResolutionObject(shortBuf)
	if err == nil {
		t.Fatal("декодер должен отклонять усеченный буфер при объявленном na")
	}
}

// Rebinding-фильтр: localhost и приватные адреса не должны попадать в объект.
func TestResolveDomainFiltersPrivate(t *testing.T) {
	AllowPrivateResolution = true
	ro, err := ResolveDomain("localhost", []byte("seed"))
	if err != nil {
		t.Fatalf("localhost с allowPrivate: %v", err)
	}
	found := false
	for _, a := range ro.Addrs {
		if a == "127.0.0.1" || a == "::1" {
			found = true
		}
	}
	if !found {
		t.Fatal("localhost не разрешился в loopback")
	}

	AllowPrivateResolution = false
	defer func() { AllowPrivateResolution = false }()
	if _, err := ResolveDomain("localhost", []byte("seed")); err == nil {
		t.Fatal("приватный адрес прошёл фильтр (rebinding-дыра)")
	}
}

// Полный поток: нода + клиент, Open("localhost:port") идёт через
// RESOLVE→OPEN с проверкой подписи на ноде. Плюс подделанный объект.
func TestDNSBoundStream(t *testing.T) {
	AllowPrivateResolution = true
	defer func() { AllowPrivateResolution = false }()

	// Эхо-сервер — «сайт».
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go io.Copy(c, c)
		}
	}()
	_, port, _ := net.SplitHostPort(echo.Addr().String())

	// Нода.
	privB64, pubB64, _ := GenerateNodeKey()
	priv, _ := ParseNodePrivKey(privB64)
	clientB64, _, _ := GenerateNodeKey()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sess, _, err := ServerHandshake(c, priv, nil)
				if err != nil {
					return
				}
				conn, err := NewServerConn(c, sess)
				if err != nil {
					return
				}
				ServeMuxWithPolicy(conn, 5*time.Second, NewPolicyEngine(DeclarativePolicy{MaxStreamsPerConn: 256}), nil)
			}()
		}
	}()

	cc, err := DialNode(ln.Addr().String(), pubB64, clientB64, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	mux := NewMuxClient(cc)

	// 1. Домен через автоматический DNS-binding (Open сам делает RESOLVE→OPEN).
	st, err := mux.Open(net.JoinHostPort("localhost", port))
	if err != nil {
		t.Fatalf("bound open: %v", err)
	}
	msg := []byte("dns-bound-privet")
	if _, err := st.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(st, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(msg) {
		t.Fatal("данные искажены")
	}
	st.Close()

	// 2. Кэш: второй Open к тому же домену не должен делать новый RESOLVE.
	mux.resMu.Lock()
	cached := mux.resCache["localhost"]
	mux.resMu.Unlock()
	if cached == nil {
		t.Fatal("resolution не закэширован — будет лишний RTT на соединение")
	}

	// 3. Подделанный объект (подпись от чужого ключа) — нода обязана отказать.
	forged := &ResolutionObject{Domain: "localhost", Addrs: []string{"127.0.0.1"}, Expiry: time.Now().Add(time.Hour).Unix()}
	forged.Sign([]byte("chyozhoy-klyuch"))
	enc, _ := EncodeTarget(net.JoinHostPort("127.0.0.1", port))
	roB := forged.Encode()
	payload := make([]byte, 0, 2+len(roB)+len(enc))
	payload = append(payload, byte(len(roB)>>8), byte(len(roB)))
	payload = append(payload, roB...)
	payload = append(payload, enc...)
	if _, err := mux.openRawAuth(payload); err == nil {
		t.Fatal("подделанный ResolutionObject принят нодой")
	} else if !strings.Contains(err.Error(), "signature") {
		t.Fatalf("ожидалась ошибка подписи, получено: %v", err)
	}

	// 4. Чужой адрес в честном объекте: Resolve localhost, но открыть 9.9.9.9.
	ro, err := mux.Resolve("localhost")
	if err != nil {
		t.Fatal(err)
	}
	enc2, _ := EncodeTarget(net.JoinHostPort("9.9.9.9", port))
	roB2 := ro.Encode()
	payload2 := make([]byte, 0, 2+len(roB2)+len(enc2))
	payload2 = append(payload2, byte(len(roB2)>>8), byte(len(roB2)))
	payload2 = append(payload2, roB2...)
	payload2 = append(payload2, enc2...)
	if _, err := mux.openRawAuth(payload2); err == nil {
		t.Fatal("адрес вне подписанного набора принят (rebinding)")
	}
}
