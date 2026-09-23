package chameleon

// cf_exogenous.go — Слой 7: экзогенная сенсорика (чужие пробы вместо своих).
//
// Мир непрерывно зондирует ТСПУ за нас: OONI публикует десятки тысяч
// измерений в сутки по RU. Этот модуль тянет публичный OONI Measurements API
// (read-only, обычный HTTPS — для DPI неотличим от веб-трафика) и нормализует
// чужие вердикты в тот же формат наблюдений, что пишет автопилот клиента в
// data/netprofile.jsonl (этап F1). Каждая запись помечена источником
// (src: own|exo) и весом доверия, чтобы recency-weighting и валидация
// суррогат-модели (cf_surrogate.go) различали свои пробы и чужие.
//
// Экономика разведки инвертирована: наблюдение стоит ноль собственной
// экспозиции и не оставляет следа у цензора. Канарейки (слой 3) остаются
// вторым эшелоном для того, чего экзогенный поток не покрывает.
//
// Safe by design: только GET к публичному API; никаких собственных проб к
// целям цензора; никаких реальных запрещённых SNI в коде.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Источники наблюдений (поле src в netprofile.jsonl).
const (
	SrcOwn = "own" // собственная проба клиента (автопилот, этап F1)
	SrcExo = "exo" // экзогенное наблюдение (OONI и т.п.)
)

// Веса доверия к источникам: своя проба точно про наш путь и наш геном,
// чужая — про чужой путь/ASN и неизвестный геном, поэтому дешевле.
const (
	TrustOwn = 1.0
	TrustExo = 0.4
)

// NetObservation — каноническая строка наблюдения «сеть -> вердикт цензора».
// JSON-имена совпадают с форматом netprofile.jsonl автопилота (cmd/chamd),
// поэтому старые (own) и новые (exo) записи сосуществуют в одном файле.
// Поля Src/Trust/UID/ProbeASN добавочные; пустой Src читается как SrcOwn
// (NormalizeObs) — обратная совместимость с записями, уже на диске.
type NetObservation struct {
	TS            string   `json:"ts"`
	Src           string   `json:"src,omitempty"`
	Trust         float64  `json:"trust,omitempty"`
	UID           string   `json:"uid,omitempty"`       // дедуп-ключ экзогенной записи
	ProbeASN      string   `json:"probe_asn,omitempty"` // AS, из которой сделано наблюдение
	HasDPI        bool     `json:"dpi"`
	DNSHijack     bool     `json:"dns_hijack"`
	TCPReset      bool     `json:"tcp_reset"`
	TLSInterf     bool     `json:"tls_interference"`
	HTTPBlockPage bool     `json:"http_block_page"`
	ResolverPlain string   `json:"resolver_plain,omitempty"`
	ResolverDoH   string   `json:"resolver_doh,omitempty"`
	BlockSigs     []string `json:"block_signatures,omitempty"`
	Actions       int      `json:"actions,omitempty"`
}

// NormalizeObs заполняет дефолты источника: записи без src/trust (старый
// формат автопилота) считаются собственными пробами с полным доверием.
func NormalizeObs(o NetObservation) NetObservation {
	if o.Src == "" {
		o.Src = SrcOwn
	}
	if o.Trust <= 0 {
		switch o.Src {
		case SrcOwn:
			o.Trust = TrustOwn
		default:
			o.Trust = TrustExo
		}
	}
	return o
}

// ObservationFromProfile переводит собственный профиль сети (этап F1) в
// каноническую запись с пометкой SrcOwn.
func ObservationFromProfile(p CensorProfile, actions int) NetObservation {
	return NetObservation{
		TS:            time.Now().UTC().Format(time.RFC3339),
		Src:           SrcOwn,
		Trust:         TrustOwn,
		HasDPI:        p.HasDPI,
		DNSHijack:     p.DNSLikelyHijack,
		TCPReset:      p.TCPResetInjection,
		TLSInterf:     p.TLSInterference,
		HTTPBlockPage: p.HTTPBlockPage,
		ResolverPlain: p.ResolverPlain,
		ResolverDoH:   p.ResolverDoH,
		BlockSigs:     p.BlockSignatures,
		Actions:       actions,
	}
}

// RecencyWeight — экспоненциальное забывание: вес записи = 0.5^(age/halfLife).
// Экзогенные записи дополнительно режутся на Trust источника (см. WeightedObs).
func RecencyWeight(ts time.Time, now time.Time, halfLife time.Duration) float64 {
	if halfLife <= 0 {
		halfLife = 7 * 24 * time.Hour
	}
	age := now.Sub(ts)
	if age < 0 {
		age = 0
	}
	return powHalf(age, halfLife)
}

func powHalf(age, halfLife time.Duration) float64 {
	// 2^(-age/halfLife) без math.Pow в горячем пути нельзя — берём math.Exp2.
	return math.Exp2(-float64(age) / float64(halfLife))
}

// WeightedObs — итоговый вес наблюдения для обучения/валидации суррогата:
// доверие к источнику * забывание по времени.
func WeightedObs(o NetObservation, now time.Time, halfLife time.Duration) float64 {
	o = NormalizeObs(o)
	ts, err := time.Parse(time.RFC3339, o.TS)
	if err != nil {
		return o.Trust // без валидного ts — только приоритет источника
	}
	return o.Trust * RecencyWeight(ts, now, halfLife)
}

// --- OONI puller ---

// OONIClient — read-only клиент публичного OONI Measurements API.
// Один GET на пачку измерений; endpoint инжектируем (для тестов).
type OONIClient struct {
	baseURL string
	hc      *http.Client
}

// NewOONIClient конструирует клиент; пустой baseURL = api.ooni.io.
func NewOONIClient(baseURL string) *OONIClient {
	if baseURL == "" {
		baseURL = "https://api.ooni.io"
	}
	return &OONIClient{baseURL: strings.TrimRight(baseURL, "/"), hc: &http.Client{Timeout: 20 * time.Second}}
}

// OONIQuery — параметры выборки измерений.
type OONIQuery struct {
	ProbeCC     string    // "RU"
	TestName    string    // "web_connectivity" (пусто = все)
	Since       time.Time // окно измерений
	Until       time.Time
	Limit       int  // за один запрос (API капит на 100)
	OnlyAnomaly bool // только anomaly/confirmed (сигнал, а не шум)
}

// ooniResult — релевантная проекция записи OONI API v1 /measurements.
type ooniResult struct {
	MeasurementUID string `json:"measurement_uid"`
	Input          string `json:"input"`
	ProbeCC        string `json:"probe_cc"`
	ProbeASN       string `json:"probe_asn"`
	TestName       string `json:"test_name"`
	StartTime      string `json:"measurement_start_time"`
	Anomaly        bool   `json:"anomaly"`
	Confirmed      bool   `json:"confirmed"`
	Failure        bool   `json:"failure"`
	CategoryCode   string `json:"category_code"`
}

type ooniResponse struct {
	Metadata struct {
		Count int `json:"count"`
	} `json:"metadata"`
	Results []ooniResult `json:"results"`
}

// FetchMeasurements делает один GET к OONI API и возвращает сырые записи.
func (c *OONIClient) FetchMeasurements(ctx context.Context, q OONIQuery) ([]ooniResult, error) {
	if q.ProbeCC == "" {
		q.ProbeCC = "RU"
	}
	if q.Limit <= 0 || q.Limit > 100 {
		q.Limit = 100
	}
	v := url.Values{}
	v.Set("probe_cc", q.ProbeCC)
	if q.TestName != "" {
		v.Set("test_name", q.TestName)
	}
	if !q.Since.IsZero() {
		v.Set("since", q.Since.UTC().Format("2006-01-02"))
	}
	if !q.Until.IsZero() {
		v.Set("until", q.Until.UTC().Format("2006-01-02"))
	}
	if q.OnlyAnomaly {
		v.Set("anomaly", "true")
	}
	v.Set("limit", fmt.Sprintf("%d", q.Limit))
	u := c.baseURL + "/api/v1/measurements?" + v.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "cham-exo/1.0")
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errHTTPStatus(resp.StatusCode)
	}
	var payload ooniResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	return payload.Results, nil
}

// FetchObservations тянет измерения и нормализует их в NetObservation.
// failure-записи OONI пропускаются: это ошибка самого зонда, не вердикт.
func (c *OONIClient) FetchObservations(ctx context.Context, q OONIQuery) ([]NetObservation, error) {
	rows, err := c.FetchMeasurements(ctx, q)
	if err != nil {
		return nil, err
	}
	out := make([]NetObservation, 0, len(rows))
	for _, r := range rows {
		if r.Failure {
			continue
		}
		out = append(out, NormalizeObs(ooniToObs(r)))
	}
	return out, nil
}

// ooniToObs маппит вердикты OONI web_connectivity на наши флаги:
// confirmed -> блок (для web-проб это почти всегда blockpage/RST у ТСПУ),
// anomaly -> DPI-интерференция без подтверждения метода.
func ooniToObs(r ooniResult) NetObservation {
	o := NetObservation{
		TS:       r.StartTime,
		Src:      SrcExo,
		Trust:    TrustExo,
		UID:      "ooni:" + r.MeasurementUID,
		ProbeASN: r.ProbeASN,
	}
	if o.TS == "" {
		o.TS = time.Now().UTC().Format(time.RFC3339)
	}
	switch {
	case r.Confirmed:
		o.HasDPI = true
		o.HTTPBlockPage = true // confirmed blocking; метод уточняется своими пробами
	case r.Anomaly:
		o.HasDPI = true // аномалия без подтверждения: слабый сигнал, низкий trust
	}
	return o
}

// --- дедуп и слияние ---

// obsKey — ключ дедупликации: у экзогенных записей есть UID, у собственных —
// временная метка + вектор вердиктов (две своих пробы в одну секунду с одним
// вердиктом неинформативны).
func obsKey(o NetObservation) string {
	if o.UID != "" {
		return o.UID
	}
	return fmt.Sprintf("%s|%v|%v|%v|%v|%v", o.TS, o.HasDPI, o.DNSHijack, o.TCPReset, o.TLSInterf, o.HTTPBlockPage)
}

// MergeObservations сливает свежие наблюдения с существующими без дублей.
// При конфликте ключа выигрывает запись с большим Trust (своя важнее чужой
// копии того же события).
func MergeObservations(existing, fresh []NetObservation) []NetObservation {
	seen := make(map[string]NetObservation, len(existing)+len(fresh))
	for _, o := range existing {
		o = NormalizeObs(o)
		seen[obsKey(o)] = o
	}
	added := 0
	for _, o := range fresh {
		o = NormalizeObs(o)
		k := obsKey(o)
		if old, dup := seen[k]; dup {
			if o.Trust > old.Trust {
				seen[k] = o
			}
			continue
		}
		seen[k] = o
		added++
	}
	_ = added
	out := make([]NetObservation, 0, len(seen))
	for _, o := range seen {
		out = append(out, o)
	}
	return out
}

// LoadObservations читает JSONL-журнал наблюдений (netprofile.jsonl).
// Битые строки пропускаются — журнал не должен ломать читателя.
func LoadObservations(path string) ([]NetObservation, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []NetObservation
	start := 0
	for i := 0; i <= len(b); i++ {
		if i < len(b) && b[i] != '\n' {
			continue
		}
		line := strings.TrimSpace(string(b[start:i]))
		start = i + 1
		if line == "" {
			continue
		}
		var o NetObservation
		if json.Unmarshal([]byte(line), &o) == nil {
			out = append(out, NormalizeObs(o))
		}
	}
	return out, nil
}

// AppendObservations дописывает наблюдения в JSONL (0600) с ротацией по
// размеру — та же дисциплина, что у автопилота (netprofileMaxBytes/keep).
// fresh сначала дедуплицируются против хвоста файла (чтобы рестарт пуллера
// не плодил копии одной выборки OONI).
func AppendObservations(path string, fresh []NetObservation, maxBytes int64, keep int) (int, error) {
	if len(fresh) == 0 {
		return 0, nil
	}
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	if keep <= 0 {
		keep = 256
	}
	existing, _ := LoadObservations(path) // отсутствие файла — не ошибка
	if len(existing) > 0 {
		tail := existing
		if len(tail) > keep {
			tail = tail[len(tail)-keep:]
		}
		seen := map[string]bool{}
		for _, o := range tail {
			seen[obsKey(o)] = true
		}
		deduped := fresh[:0]
		for _, o := range fresh {
			if !seen[obsKey(NormalizeObs(o))] {
				deduped = append(deduped, o)
			}
		}
		fresh = deduped
		if len(fresh) == 0 {
			return 0, nil
		}
	}
	if st, err := os.Stat(path); err == nil && st.Size() > maxBytes {
		all, _ := LoadObservations(path)
		if len(all) > keep {
			all = all[len(all)-keep:]
		}
		var sb strings.Builder
		for _, o := range all {
			b, err := json.Marshal(NormalizeObs(o))
			if err == nil {
				sb.Write(b)
				sb.WriteByte('\n')
			}
		}
		if err := os.WriteFile(path, []byte(sb.String()), 0o600); err != nil {
			return 0, err
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	n := 0
	for _, o := range fresh {
		b, err := json.Marshal(NormalizeObs(o))
		if err != nil {
			continue
		}
		if _, err := f.Write(append(b, '\n')); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// ErrExoNoData — пуллер отработал, но свежих наблюдений нет (не ошибка пути).
var ErrExoNoData = errors.New("cf-exo: no fresh observations in window")
