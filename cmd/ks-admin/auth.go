//go:build linux

// Доступ к панели: логин/пароль (scrypt), сессии-cookie, защита от перебора,
// самоподписанный TLS. Пароль в открытом виде нигде не хранится.
package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

const (
	scryptN     = 1 << 15
	scryptR     = 8
	scryptP     = 1
	scryptKeyLn = 32
	sessTTL     = 12 * time.Hour
	cookieName  = "ksadm"
	limWindow   = 5 * time.Minute
	limMax      = 6
	csrfCookie  = "ksadm_csrf"
	csrfTTL     = 30 * time.Minute
)

type adminConf struct {
	User string
	Salt []byte
	Hash []byte
}

var (
	conf     *adminConf
	sessions *sessStore
	lim      *limiter
)

func hashPass(pass string, salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(pass), salt, scryptN, scryptR, scryptP, scryptKeyLn)
}

func randBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func randToken(n int) (string, error) {
	b, err := randBytes(n)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func loadConf(path string) (*adminConf, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &adminConf{}
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		k, v, ok := strings.Cut(ln, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "user":
			c.User = v
		case "salt":
			c.Salt, _ = base64.StdEncoding.DecodeString(v)
		case "hash":
			c.Hash, _ = base64.StdEncoding.DecodeString(v)
		}
	}
	if c.User == "" || len(c.Salt) == 0 || len(c.Hash) == 0 {
		return nil, fmt.Errorf("в %s нет полей user/salt/hash", path)
	}
	return c, nil
}

func saveConf(path string, c *adminConf) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	body := fmt.Sprintf("# ks-admin: доступ к панели. Хранится только хеш пароля (scrypt).\nuser = %s\nsalt = %s\nhash = %s\n",
		c.User, base64.StdEncoding.EncodeToString(c.Salt), base64.StdEncoding.EncodeToString(c.Hash))
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ensureConf читает конфиг, а если его нет - создаёт со случайным паролем,
// который возвращается вторым значением ровно один раз.
func ensureConf(path, user string) (*adminConf, string, error) {
	if c, err := loadConf(path); err == nil {
		return c, "", nil
	}
	pw, err := randToken(12)
	if err != nil {
		return nil, "", err
	}
	salt, err := randBytes(16)
	if err != nil {
		return nil, "", err
	}
	h, err := hashPass(pw, salt)
	if err != nil {
		return nil, "", err
	}
	c := &adminConf{User: user, Salt: salt, Hash: h}
	if err := saveConf(path, c); err != nil {
		return nil, "", err
	}
	return c, pw, nil
}

func setPassword(path, user string) error {
	pw := os.Getenv("KS_ADMIN_PASS")
	if pw == "" {
		fmt.Fprint(os.Stderr, "новый пароль: ")
		s, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && strings.TrimSpace(s) == "" {
			return err
		}
		pw = strings.TrimSpace(s)
	}
	if len(pw) < 8 {
		return fmt.Errorf("пароль короче 8 символов")
	}
	salt, err := randBytes(16)
	if err != nil {
		return err
	}
	h, err := hashPass(pw, salt)
	if err != nil {
		return err
	}
	return saveConf(path, &adminConf{User: user, Salt: salt, Hash: h})
}

func checkPass(c *adminConf, user, pass string) bool {
	if c == nil {
		return false
	}
	uOK := subtle.ConstantTimeCompare([]byte(user), []byte(c.User)) == 1
	h, err := hashPass(pass, c.Salt)
	if err != nil {
		return false
	}
	pOK := subtle.ConstantTimeCompare(h, c.Hash) == 1
	return uOK && pOK
}

// ---------- сессии ----------

type sessStore struct {
	mu sync.Mutex
	m  map[string]time.Time
}

func newSessStore() *sessStore { return &sessStore{m: map[string]time.Time{}} }

func (s *sessStore) create() (string, error) {
	t, err := randToken(32)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.m[t] = time.Now().Add(sessTTL)
	s.mu.Unlock()
	return t, nil
}

func (s *sessStore) valid(t string) bool {
	if t == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.m[t]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(s.m, t)
		return false
	}
	return true
}

func (s *sessStore) drop(t string) {
	s.mu.Lock()
	delete(s.m, t)
	s.mu.Unlock()
}

func (s *sessStore) gc() {
	now := time.Now()
	s.mu.Lock()
	for k, v := range s.m {
		if now.After(v) {
			delete(s.m, k)
		}
	}
	s.mu.Unlock()
}

func (s *sessStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}

// ---------- защита от перебора ----------

type limiter struct {
	mu    sync.Mutex
	fails map[string][]time.Time
}

func newLimiter() *limiter { return &limiter{fails: map[string][]time.Time{}} }

func (l *limiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cut := time.Now().Add(-limWindow)
	keep := l.fails[ip][:0]
	for _, t := range l.fails[ip] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	l.fails[ip] = keep
	return len(keep) < limMax
}

func (l *limiter) fail(ip string) {
	l.mu.Lock()
	l.fails[ip] = append(l.fails[ip], time.Now())
	l.mu.Unlock()
}

func (l *limiter) reset(ip string) {
	l.mu.Lock()
	delete(l.fails, ip)
	l.mu.Unlock()
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func hostOnly(h string) string {
	if x, _, err := net.SplitHostPort(h); err == nil {
		return x
	}
	return h
}

// sameOrigin proveryaet istochnik POST-zaprosa.
// Vazhno: pri Referrer-Policy: no-referrer brauzer po standartu Fetch
// prisylaet "Origin: null" i ne prisylaet Referer. Eto ne poddelka, a
// obezlichenniy istochnik - ranshe takoy zapros otklonyalsya, i vhod iz
// brauzera byl nevozmozhen. Teper obezlichenniy istochnik propuskaetsya,
// a ot poddelki zaschischaet csrf-token formy + SameSite-cookie.
func sameOrigin(r *http.Request) bool {
	src := r.Header.Get("Origin")
	if src == "" || src == "null" {
		src = r.Header.Get("Referer")
	}
	if src == "" || src == "null" {
		return true
	}
	u, err := url.Parse(src)
	if err != nil || u.Host == "" {
		return true
	}
	if strings.EqualFold(u.Host, r.Host) {
		return true
	}
	return strings.EqualFold(hostOnly(u.Host), hostOnly(r.Host))
}

// issueCSRF vydayot (ili prodlevaet) token formy vhoda: cookie + skrytoe pole.
func issueCSRF(w http.ResponseWriter, r *http.Request) string {
	tok := ""
	if ck, err := r.Cookie(csrfCookie); err == nil && len(ck.Value) >= 16 {
		tok = ck.Value
	}
	if tok == "" {
		t, err := randToken(24)
		if err != nil {
			return ""
		}
		tok = t
	}
	http.SetCookie(w, &http.Cookie{
		Name: csrfCookie, Value: tok, Path: "/login", HttpOnly: true,
		Secure: *fTLS, SameSite: http.SameSiteStrictMode, MaxAge: int(csrfTTL.Seconds()),
	})
	return tok
}

// csrfOK sveryaet skrytoe pole formy s cookie (double submit).
func csrfOK(r *http.Request) bool {
	ck, err := r.Cookie(csrfCookie)
	if err != nil || ck.Value == "" {
		return false
	}
	got := r.PostFormValue("csrf")
	if got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(ck.Value), []byte(got)) == 1
}

// loginPage risuet formu vhoda i vsegda vydayot svezhiy csrf-token.
func loginPage(w http.ResponseWriter, r *http.Request, msg string, status int) {
	renderLogin(w, msg, status, issueCSRF(w, r))
}

// ---------- доступ ----------

func requireAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ck, err := r.Cookie(cookieName)
		if err != nil || !sessions.valid(ck.Value) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.Error(w, "не авторизовано", http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		h(w, r)
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		loginPage(w, r, "", http.StatusOK)
	case http.MethodPost:
		ip := clientIP(r)
		if !lim.allow(ip) {
			addEvent("WARN", "ks-admin", "перебор пароля с адреса "+ip+" - временная блокировка")
			loginPage(w, r, "Слишком много попыток. Подождите несколько минут.", http.StatusTooManyRequests)
			return
		}
		if err := r.ParseForm(); err != nil {
			loginPage(w, r, "Некорректная форма.", http.StatusBadRequest)
			return
		}
		if !sameOrigin(r) {
			log.Printf("отказ по источнику: origin=%q referer=%q host=%q ip=%s", r.Header.Get("Origin"), r.Header.Get("Referer"), r.Host, ip)
			addEvent("WARN", "ks-admin", "вход отклонён: посторонний источник запроса с адреса "+ip)
			loginPage(w, r, "Запрос отклонён (проверка источника).", http.StatusForbidden)
			return
		}
		if !csrfOK(r) {
			log.Printf("отказ по csrf: ip=%s", ip)
			loginPage(w, r, "Форма входа устарела - попробуйте ещё раз.", http.StatusForbidden)
			return
		}
		u := strings.TrimSpace(r.PostFormValue("user"))
		p := r.PostFormValue("pass")
		if !checkPass(conf, u, p) {
			lim.fail(ip)
			log.Printf("неудачный вход: %q с %s", u, ip)
			addEvent("WARN", "ks-admin", fmt.Sprintf("неудачный вход в панель: %q с адреса %s", u, ip))
			loginPage(w, r, "Неверный логин или пароль.", http.StatusUnauthorized)
			return
		}
		lim.reset(ip)
		tok, err := sessions.create()
		if err != nil {
			loginPage(w, r, "Внутренняя ошибка.", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name: cookieName, Value: tok, Path: "/", HttpOnly: true,
			Secure: *fTLS, SameSite: http.SameSiteLaxMode, MaxAge: int(sessTTL.Seconds()),
		})
		http.SetCookie(w, &http.Cookie{
			Name: csrfCookie, Value: "", Path: "/login", MaxAge: -1, HttpOnly: true,
			Secure: *fTLS, SameSite: http.SameSiteStrictMode,
		})
		log.Printf("вход в панель: %q с %s", u, ip)
		addEvent("INFO", "ks-admin", fmt.Sprintf("вход в панель: %q с адреса %s", u, ip))
		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "метод не поддерживается", http.StatusMethodNotAllowed)
	}
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if ck, err := r.Cookie(cookieName); err == nil {
		sessions.drop(ck.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		Secure: *fTLS, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---------- TLS ----------

func ensureCert(dir string) (tls.Certificate, error) {
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if c, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		return c, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "ks-admin"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"ks-admin", "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	if v := os.Getenv("KS_ADMIN_IP"); v != "" {
		for _, part := range strings.Split(v, ",") {
			if p := net.ParseIP(strings.TrimSpace(part)); p != nil {
				tpl.IPAddresses = append(tpl.IPAddresses, p)
			}
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	log.Printf("создан самоподписанный сертификат %s", certPath)
	return tls.X509KeyPair(certPEM, keyPEM)
}
