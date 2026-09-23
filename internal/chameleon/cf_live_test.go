package chameleon

// cf_live_test.go — живые проверки против реального интернета (не loopback):
// публичные DoH-резолверы двух независимых операторов, crt.sh (CT-логи),
// внешний bulletin board на Cloudflare Workers. Это те самые плоскости,
// через которые control-plane пойдёт в бою поверх трафика провайдера.
//
// Все тесты skip при отсутствии сети (как существующие TestDoHReal /
// TestBGPBeaconSnapshot) — они доказывают достижимость и контракт ответа
// реальных сервисов, а не заменяют полевую проверку на сети владельца (B4).

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// Публичный DoH Cloudflare: TXT-резолв через HTTPS — основа читателя этапа C2.
func TestLiveDoHCloudflare(t *testing.T) {
	r := NewDoHResolver("https://1.1.1.1/dns-query")
	txts, err := r.ResolveTXT("google.com")
	if err != nil {
		t.Skipf("offline: %v", err)
	}
	if len(txts) == 0 {
		t.Fatal("DoH 1.1.1.1 вернул пустой TXT-набор для google.com")
	}
	t.Logf("DoH 1.1.1.1: %d TXT-записей, первая %.40s...", len(txts), txts[0])
}

// Публичный DoH Quad9 (второй независимый резолвер из roadmap C2).
func TestLiveDoHQuad9(t *testing.T) {
	// Стандартный 443 endpoint (порт 5053 часто закрыт на egress-файрволах).
	r := NewDoHResolver("https://dns.quad9.net/dns-query")
	txts, err := r.ResolveTXT("google.com")
	if err != nil {
		t.Skipf("offline: %v", err)
	}
	if len(txts) == 0 {
		t.Fatal("DoH quad9 вернул пустой TXT-набор для google.com")
	}
	t.Logf("DoH quad9: %d TXT-записей", len(txts))
}

// A-резолв через DoH — путь автопилота при перехвате DNS провайдером.
func TestLiveDoHResolveA(t *testing.T) {
	r := NewDoHResolver("")
	ips, err := r.ResolveA(context.Background(), "one.one.one.one")
	if err != nil {
		t.Skipf("offline: %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("DoH ResolveA: пустой ответ для one.one.one.one")
	}
	t.Logf("DoH ResolveA one.one.one.one -> %v", ips)
}

// crt.sh: реальный CT-поиск по HTTPS — читатель этапа D1 против боевого
// сервиса. Зона github.com: наших меток нет, но контракт API (JSON-массив
// с id/name_value) обязан парситься.
func TestLiveCTLogFetch(t *testing.T) {
	r := NewCTLogReader("github.com", "zq")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// crt.sh публично флакает (частые 5xx под нагрузкой) — до 4 попыток.
	var entries []ctEntry
	var err error
	for attempt := 1; attempt <= 4; attempt++ {
		entries, err = r.fetch(ctx)
		if err == nil {
			break
		}
		time.Sleep(time.Duration(attempt) * 2 * time.Second)
	}
	if err != nil {
		t.Skipf("offline: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("crt.sh вернул 0 записей для github.com — контракт API сломан?")
	}
	// Наших меток в чужой зоне нет — ReadMessage обязан честно сказать об этом.
	if _, err := r.ReadMessage(ctx); err == nil {
		t.Fatal("в чужой зоне без наших меток ReadMessage обязан вернуть ошибку")
	}
	t.Logf("crt.sh: %d записей по github.com, парсинг+фильтрация OK", len(entries))
}

// Внешний bulletin board (Cloudflare Workers): достижимость по HTTPS — канал,
// переживающий блокировку IP ноды. Без write-токена доступна только проверка
// связности/чтения.
func TestLiveBoardWorkerReachable(t *testing.T) {
	hc := &http.Client{Timeout: 12 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "https://cham-bulletin.your-account.workers.dev/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	resp, err := hc.Do(req)
	if err != nil {
		t.Skipf("offline: %v", err)
	}
	defer resp.Body.Close()
	// Любой HTTP-ответ (200/400/403/404) доказывает связность до воркера.
	t.Logf("board worker: HTTP %d — достижим", resp.StatusCode)
}
