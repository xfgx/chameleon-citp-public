package chameleon

// cf_ctlog_test.go — Этап D1: парсер crt.sh на сохранённом ответе (fixture)
// и кодирование label'ов. Живой прогон против настоящего crt.sh — в
// cf_live_test.go.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Кодирование label туда-обратно + фильтрация чужих меток.
func TestCTLabelCodec(t *testing.T) {
	chunk := []byte("next-entry=10.0.0.7:8443;profile=r1")
	label := CTEncodeLabel("zq", chunk)
	if len(label) > 63 {
		t.Fatalf("label длиннее DNS-предела: %d", len(label))
	}
	got, err := ctDecodeLabel("zq", label)
	if err != nil || string(got) != string(chunk) {
		t.Fatalf("roundtrip: got %q err=%v", got, err)
	}
	// Чужой префикс — ошибка.
	if _, err := ctDecodeLabel("zz", label); err == nil {
		t.Fatal("чужой префикс должен отбрасываться")
	}
	// Битый base32 — ошибка, а не паника.
	if _, err := ctDecodeLabel("zq", "zq!!!***"); err == nil {
		t.Fatal("невалидный base32 должен отбрасываться")
	}
	// Максимальный чанк помещается в 63 символа.
	big := make([]byte, CTMaxChunk)
	for i := range big {
		big[i] = byte(i)
	}
	if l := len(CTEncodeLabel("zq", big)); l > 63 {
		t.Fatalf("CTMaxChunk=%d даёт label %d > 63", CTMaxChunk, l)
	}
}

// Сохранённый ответ crt.sh: записи вразнобой, мусорные метки чужих
// поддоменов, многострочные name_value — как в реальной выдаче.
func TestCTLogReadMessageFixture(t *testing.T) {
	part1 := []byte("SID=demo;next=")
	part2 := []byte("entry=10.0.0.9:443")
	l1 := CTEncodeLabel("zq", part1)
	l2 := CTEncodeLabel("zq", part2)
	fixture := fmt.Sprintf(`[
		{"id": 1002, "name_value": "%s.example.com\nwww.example.com"},
		{"id": 1001, "name_value": "%s.example.com"},
		{"id": 1003, "name_value": "mail.example.com\nzq!!!.example.com"},
		{"id": 1004, "name_value": "%s.other-zone.net"}
	]`, l2, l1, l2)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("output") != "json" {
			http.Error(w, "bad", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fixture))
	}))
	defer srv.Close()

	r := NewCTLogReader("example.com", "zq").WithBaseURL(srv.URL)
	got, err := r.ReadMessage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := string(part1) + string(part2)
	if string(got) != want {
		t.Fatalf("сборка по cert ID: got %q want %q", got, want)
	}
}

// Пустая зона / отсутствие наших меток — честная ошибка.
func TestCTLogNoChannelLabels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"id":1,"name_value":"www.example.com"}]`))
	}))
	defer srv.Close()
	r := NewCTLogReader("example.com", "zq").WithBaseURL(srv.URL)
	if _, err := r.ReadMessage(context.Background()); err == nil {
		t.Fatal("ожидалась ошибка 'no channel labels'")
	}
}

// Писатель CT-доски до покупки домена — честный stub (сквозное правило 4).
func TestCTLogWriterStub(t *testing.T) {
	if err := PublishCTLog(context.Background(), "example.com", []byte("x")); err != ErrRequiresInfrastructure {
		t.Fatalf("ожидался ErrRequiresInfrastructure, got %v", err)
	}
}
