package chameleon

// cf_ctlog.go — Этап D1: CT-логи (Certificate Transparency) как публичная
// доска объявлений.
//
// Идея направления 3: нода выпускает сертификаты (Let's Encrypt) на
// поддомены, кодирующие данные в label'ах; клиент читает crt.sh по HTTPS —
// канал глобально видим и не касается IP ноды вообще. Узко (лимиты LE
// ~50 серт/нед/домен), но реально.
//
// Кодирование: чанк -> base32 (STD, без паддинга, lowercase) в левый label
// с префиксом оператора (напр. "z"): z<nbs...>.example.com. Один label — до
// 63 символов, т.е. до ~38 байт полезной нагрузки на сертификат.
//
// Читатель здесь — полностью боевой (crt.sh по HTTPS). Писатель требует
// своей зоны (этап C1: регистрация домена — блокер владельца) и ACME-клиента;
// до тех пор — честный stub ErrRequiresInfrastructure (сквозное правило 4).

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// CTMaxChunk — максимум полезных байт в одном label (63 символа base32
// без префикса и паддинга).
const CTMaxChunk = 38

// CTLogReader читает доску через публичный CT-лог поиск (crt.sh).
type CTLogReader struct {
	zone   string // зона ноды, напр. "example.com"
	prefix string // префикс меток канала, напр. "z" (конфигурация оператора)
	base   string // базовый URL crt.sh-совместимого API
	hc     *http.Client
}

// NewCTLogReader — читатель CT-доски для зоны zone; prefix выбирает метки
// нашего канала среди прочих поддоменов зоны.
func NewCTLogReader(zone, prefix string) *CTLogReader {
	return &CTLogReader{
		zone:   strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), "."),
		prefix: prefix,
		base:   "https://crt.sh",
		hc:     &http.Client{Timeout: 15 * time.Second},
	}
}

// WithBaseURL подменяет endpoint (тесты на локальном httptest).
func (r *CTLogReader) WithBaseURL(u string) *CTLogReader {
	r.base = strings.TrimRight(u, "/")
	return r
}

// WithHTTPClient подменяет http-клиента (тесты/таймауты).
func (r *CTLogReader) WithHTTPClient(hc *http.Client) *CTLogReader {
	r.hc = hc
	return r
}

// CTEncodeLabel кодирует чанк в label: prefix + base32(nopad, lowercase).
// Обратная операция — ctDecodeLabel. Функция экспортирована, т.к. писатель
// (будущий ACME-выпуск) должен кодировать идентично читателю.
func CTEncodeLabel(prefix string, chunk []byte) string {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(chunk)
	return prefix + strings.ToLower(enc)
}

// ctDecodeLabel декодирует label обратно в чанк; ошибка — если метка не
// начинается с префикса канала или не является валидным base32.
func ctDecodeLabel(prefix, label string) ([]byte, error) {
	if !strings.HasPrefix(label, prefix) {
		return nil, fmt.Errorf("ct: label %q without channel prefix", label)
	}
	enc := strings.ToUpper(label[len(prefix):])
	for len(enc)%8 != 0 {
		enc += "="
	}
	return base32.StdEncoding.DecodeString(enc)
}

// ctEntry — запись ответа crt.sh (output=json).
type ctEntry struct {
	ID        int64  `json:"id"`
	NameValue string `json:"name_value"`
}

// fetch тянет JSON-выдачу crt.sh по зоне: /?q=%25.<zone>&output=json.
func (r *CTLogReader) fetch(ctx context.Context) ([]ctEntry, error) {
	if r.zone == "" {
		return nil, fmt.Errorf("ct: empty zone")
	}
	u := fmt.Sprintf("%s/?q=%%25.%s&output=json", r.base, url.QueryEscape(r.zone))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	resp, err := r.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ct: http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	var entries []ctEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("ct: bad crt.sh json: %w", err)
	}
	return entries, nil
}

// ReadMessage собирает полезную нагрузку доски: все метки нашего префикса в
// нашей зоне декодируются и конкатенируются в порядке cert ID (crt.sh ID
// монотонен со временем попадания в лог — это порядок публикации ноды).
func (r *CTLogReader) ReadMessage(ctx context.Context) ([]byte, error) {
	entries, err := r.fetch(ctx)
	if err != nil {
		return nil, err
	}
	type piece struct {
		id    int64
		chunk []byte
	}
	var pieces []piece
	suffix := "." + r.zone
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
			if !strings.HasSuffix(name, suffix) {
				continue
			}
			label := strings.Split(strings.TrimSuffix(name, suffix), ".")[0]
			chunk, err := ctDecodeLabel(r.prefix, label)
			if err != nil || len(chunk) == 0 {
				continue // чужая метка зоны / не наш формат
			}
			pieces = append(pieces, piece{e.ID, chunk})
		}
	}
	if len(pieces) == 0 {
		return nil, fmt.Errorf("ct: no channel labels found in zone %s", r.zone)
	}
	sort.Slice(pieces, func(i, j int) bool { return pieces[i].id < pieces[j].id })
	var out []byte
	for _, p := range pieces {
		out = append(out, p.chunk...)
	}
	return out, nil
}

// PublishCTLog — писатель CT-доски. Требует своей зоны (домен из этапа C1) и
// ACME-выпуска сертификатов (Let's Encrypt). До появления инфраструктуры —
// честный stub, имитации не делаем (сквозное правило 4).
func PublishCTLog(ctx context.Context, zone string, msg []byte) error {
	return ErrRequiresInfrastructure
}
