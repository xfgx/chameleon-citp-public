package chameleon

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Рукопожатие "Хамелон v2.1" — аутентифицированное, неотвечаемое,
// с персональными ключами клиентов (как WireGuard).
//
// У ноды есть статическая пара X25519; клиент знает её публичный ключ P_s.
// У КАЖДОГО устройства-клиента — своя пара; нода держит белый список
// публичных клиентских ключей: потерянный телефон отзывается удалением
// строки из списка, остальные устройства не затрагиваются.
//
//	Клиент → Сервер:  E_c (32 B) || AEAD(k1, ts8 || nonce16 || clientPub32) = 104 байта
//	Сервер → Клиент:  AEAD(k2, E_s32 || s_nonce16)                          = 64 байта
//
//	k1/k2 = HKDF(X25519(e_c, S), salt=E_c)  — расшифровать client hello
//	может только владелец приватного ключа ноды. Зонд из случайных байт
//	не расшифровывается → сервер МОЛЧИТ (ни одного байта ответа), а
//	соединение уходит в blackhole. Клиент не из белого списка — то же
//	молчание: снаружи неотличимо.
//
// Проверки сервера: AEAD-тег, метка времени (±60 с), nonce не в
// replay-кэше, clientPub в белом списке. Любая ошибка → молчание,
// одинаковое по таймингу.
//
// Сессионные ключи выводятся из ЭФЕМЕРНОГО ECDH(e_c, e_s): утечка
// статического ключа не раскрывает записанные сеансы (forward secrecy).
const (
	clientHelloLen  = 32 + 56 + 16 // E_c || (ts+nonce+clientPub) || tag
	serverHelloLen  = 48 + 16      // (E_s+nonce) || tag
	authClockSkew   = 60 * time.Second
	replayTTL       = 2 * authClockSkew
	handshakeTimout = 15 * time.Second
)

// ErrAuth — рукопожатие не аутентифицировано (зонд/мусор/replay).
// Сервер в этом случае обязан молчать (см. Blackhole).
var ErrAuth = errors.New("handshake auth failed")

var serverReplay = newReplayCache()

// Session — результат рукопожатия.
type Session struct {
	Seed    []byte
	SendKey []byte
	RecvKey []byte
}

func hkdfKey(secret, salt []byte, info string, n int) ([]byte, error) {
	return hkdf.Key(sha256.New, secret, salt, info, n)
}

// seal/open для рукопожатия: ключ одноразовый (выводится из свежего
// эфемерного ECDH на каждый сеанс), поэтому нулевой nonce безопасен —
// пара (ключ, nonce) никогда не повторяется.
func seal(key, plaintext []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	return aead.Seal(nil, nonce, plaintext, nil), nil
}

func open(key, ciphertext []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	return aead.Open(nil, nonce, ciphertext, nil)
}

func deriveSession(shared, transcript []byte, isClient bool) (*Session, error) {
	seed, err := hkdfKey(shared, transcript, "session-seed", 32)
	if err != nil {
		return nil, err
	}
	c2s, err := hkdfKey(shared, transcript, "c2s-key", 32)
	if err != nil {
		return nil, err
	}
	s2c, err := hkdfKey(shared, transcript, "s2c-key", 32)
	if err != nil {
		return nil, err
	}
	s := &Session{Seed: seed}
	if isClient {
		s.SendKey, s.RecvKey = c2s, s2c
	} else {
		s.SendKey, s.RecvKey = s2c, c2s
	}
	return s, nil
}

// ClientHandshake — сторона клиента. serverPub — публичный ключ ноды,
// clientPriv — персональный ключ устройства (нода проверяет его по
// белому списку). Без них говорить с нодой v2.1 невозможно.
func ClientHandshake(c net.Conn, serverPub *ecdh.PublicKey, clientPriv *ecdh.PrivateKey) (*Session, error) {
	if serverPub == nil {
		return nil, fmt.Errorf("не задан публичный ключ ноды")
	}
	if clientPriv == nil {
		return nil, fmt.Errorf("не задан ключ клиента")
	}
	_ = c.SetDeadline(time.Now().Add(handshakeTimout))
	defer c.SetDeadline(time.Time{})

	epriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ecPub := epriv.PublicKey().Bytes()

	authShared, err := epriv.ECDH(serverPub)
	if err != nil {
		return nil, err
	}
	k1, err := hkdfKey(authShared, ecPub, "cham2-auth-c2s", 32)
	if err != nil {
		return nil, err
	}

	var payload [56]byte
	binary.BigEndian.PutUint64(payload[:8], uint64(time.Now().Unix()))
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	copy(payload[8:24], nonce[:])
	copy(payload[24:], clientPriv.PublicKey().Bytes())

	sealed, err := seal(k1, payload[:])
	if err != nil {
		return nil, err
	}
	hello := append(append([]byte{}, ecPub...), sealed...)
	if _, err := c.Write(hello); err != nil {
		return nil, fmt.Errorf("send client hello: %w", err)
	}

	reply := make([]byte, serverHelloLen)
	if _, err := io.ReadFull(c, reply); err != nil {
		return nil, fmt.Errorf("нода молчит или не наша: %w", err)
	}
	k2, err := hkdfKey(authShared, ecPub, "cham2-auth-s2c", 32)
	if err != nil {
		return nil, err
	}
	plain, err := open(k2, reply)
	if err != nil || len(plain) != 48 {
		return nil, errors.New("нода не прошла аутентификацию: это не наш сервер")
	}
	esPub, err := ecdh.X25519().NewPublicKey(plain[:32])
	if err != nil {
		return nil, fmt.Errorf("bad server ephemeral: %w", err)
	}
	sessShared, err := epriv.ECDH(esPub)
	if err != nil {
		return nil, err
	}
	return deriveSession(sessShared, transcript(ecPub, payload[:], plain), true)
}

// ServerHandshake — сторона сервера. При ЛЮБОЙ ошибке аутентификации
// возвращает ErrAuth, ничего не отправляя: вызывающий код должен
// увести соединение в Blackhole, чтобы нода была неотличима от
// мёртвого сервиса. allowlist — белый список публичных ключей клиентов
// (nil/пустой = принимать всех, кто знает ключ ноды). При успехе
// возвращает также публичный ключ клиента (для журнала).
func ServerHandshake(c net.Conn, staticPriv *ecdh.PrivateKey, allowlist map[[32]byte]bool) (*Session, []byte, error) {
	_ = c.SetDeadline(time.Now().Add(handshakeTimout))
	defer c.SetDeadline(time.Time{})

	hello := make([]byte, clientHelloLen)
	if _, err := io.ReadFull(c, hello); err != nil {
		return nil, nil, fmt.Errorf("recv client hello: %w", err)
	}
	ecPub, err := ecdh.X25519().NewPublicKey(hello[:32])
	if err != nil {
		return nil, nil, ErrAuth
	}
	authShared, err := staticPriv.ECDH(ecPub)
	if err != nil {
		return nil, nil, ErrAuth
	}
	k1, err := hkdfKey(authShared, hello[:32], "cham2-auth-c2s", 32)
	if err != nil {
		return nil, nil, ErrAuth
	}
	payload, err := open(k1, hello[32:])
	if err != nil || len(payload) != 56 {
		return nil, nil, ErrAuth // зонд/мусор: молчим
	}
	ts := int64(binary.BigEndian.Uint64(payload[:8]))
	if d := time.Since(time.Unix(ts, 0)); d < -authClockSkew || d > authClockSkew {
		return nil, nil, ErrAuth // replay со старой меткой
	}
	var nonce [16]byte
	copy(nonce[:], payload[8:24])
	if serverReplay.seenOrAdd(nonce, replayTTL) {
		return nil, nil, ErrAuth // replay: тот же ответ, что зонду — молчание
	}
	clientPub := payload[24:56]
	if len(allowlist) > 0 {
		var cp [32]byte
		copy(cp[:], clientPub)
		if !allowlist[cp] {
			return nil, nil, ErrAuth // чужое устройство: молчим
		}
	}

	spriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	var replyPayload [48]byte
	copy(replyPayload[:32], spriv.PublicKey().Bytes())
	if _, err := rand.Read(replyPayload[32:]); err != nil {
		return nil, nil, err
	}
	k2, err := hkdfKey(authShared, hello[:32], "cham2-auth-s2c", 32)
	if err != nil {
		return nil, nil, err
	}
	sealed, err := seal(k2, replyPayload[:])
	if err != nil {
		return nil, nil, err
	}
	if _, err := c.Write(sealed); err != nil {
		return nil, nil, fmt.Errorf("send server hello: %w", err)
	}
	sessShared, err := spriv.ECDH(ecPub)
	if err != nil {
		return nil, nil, err
	}
	sess, err := deriveSession(sessShared, transcript(hello[:32], payload, replyPayload[:]), false)
	if err != nil {
		return nil, nil, err
	}
	return sess, clientPub, nil
}

func transcript(ecPub, clientPayload, serverPayload []byte) []byte {
	t := make([]byte, 0, 5+32+24+48)
	t = append(t, "CHAM2"...)
	t = append(t, ecPub...)
	t = append(t, clientPayload...)
	t = append(t, serverPayload...)
	return t
}

// Blackhole — поведение при провале аутентификации: ни байта ответа,
// молча поглощаем всё, что пришлёт зонд, пока он сам не отвалится
// или не истечёт таймаут. Ресурсно дёшево (io.Copy в Discard),
// а зондирующему жжёт время и не даёт никакой информации.
func Blackhole(c net.Conn, maxHold time.Duration) {
	_ = c.SetDeadline(time.Now().Add(maxHold))
	_, _ = io.Copy(io.Discard, c)
}
