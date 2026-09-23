package chameleon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Пуллер OONI: mock-сервер отдаёт ответ формата API v1; проверяем запрос,
// нормализацию вердиктов, src-теги и отброс failure-записей.
func TestOONIFetchObservations(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("probe_cc"); got != "RU" {
			t.Errorf("probe_cc = %q, want RU", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"metadata": map[string]any{"count": 3},
			"results": []map[string]any{
				{"measurement_uid": "m1", "probe_cc": "RU", "probe_asn": "AS12345", "test_name": "web_connectivity", "measurement_start_time": "2026-08-28 10:00:00", "confirmed": true, "anomaly": true, "failure": false, "input": "https://example.com/"},
				{"measurement_uid": "m2", "probe_cc": "RU", "probe_asn": "AS12345", "test_name": "web_connectivity", "measurement_start_time": "2026-08-28 10:01:00", "confirmed": false, "anomaly": true, "failure": false},
				{"measurement_uid": "m3", "probe_cc": "RU", "test_name": "web_connectivity", "measurement_start_time": "2026-08-28 10:02:00", "failure": true},
			},
		})
	}))
	defer srv.Close()

	c := NewOONIClient(srv.URL)
	obs, err := c.FetchObservations(context.Background(), OONIQuery{ProbeCC: "RU", TestName: "web_connectivity", Limit: 50})
	if err != nil {
		t.Fatalf("FetchObservations: %v", err)
	}
	if len(obs) != 2 { // failure-запись отброшена
		t.Fatalf("got %d observations, want 2", len(obs))
	}
	if obs[0].Src != SrcExo || obs[0].Trust != TrustExo {
		t.Fatalf("src/trust: %+v", obs[0])
	}
	if obs[0].UID != "ooni:m1" || !obs[0].HTTPBlockPage || !obs[0].HasDPI {
		t.Fatalf("confirmed mapping: %+v", obs[0])
	}
	if obs[1].HTTPBlockPage || !obs[1].HasDPI {
		t.Fatalf("anomaly mapping: %+v", obs[1])
	}
	if obs[0].ProbeASN != "AS12345" {
		t.Fatalf("probe asn: %+v", obs[0])
	}
}

func TestMergeObservationsDedup(t *testing.T) {
	own := NormalizeObs(NetObservation{TS: "2026-08-28T10:00:00Z", Src: SrcOwn, HasDPI: true})
	exo := NetObservation{TS: "2026-08-28T10:00:00Z", UID: "ooni:x", Src: SrcExo}
	exoDup := NetObservation{TS: "2026-08-28T10:05:00Z", UID: "ooni:x", Src: SrcExo}
	merged := MergeObservations([]NetObservation{own, exo}, []NetObservation{exoDup})
	if len(merged) != 2 {
		t.Fatalf("merged %d, want 2", len(merged))
	}
	// Конфликт ключа: своя запись сильнее чужой копии того же события.
	exoAsOwn := NetObservation{TS: own.TS, HasDPI: true, Src: SrcOwn, Trust: TrustOwn}
	exoSameKey := NetObservation{TS: own.TS, HasDPI: true, Src: SrcExo, Trust: TrustExo}
	m2 := MergeObservations([]NetObservation{exoSameKey}, []NetObservation{exoAsOwn})
	if len(m2) != 1 || m2[0].Src != SrcOwn {
		t.Fatalf("trust conflict resolution: %+v", m2)
	}
}

func TestRecencyWeightAndTrust(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	hl := 24 * time.Hour
	ts := now.Add(-hl)
	if w := RecencyWeight(ts, now, hl); w < 0.49 || w > 0.51 {
		t.Fatalf("recency at half-life = %v, want ~0.5", w)
	}
	o := NetObservation{TS: ts.Format(time.RFC3339), Src: SrcExo}
	if ww := WeightedObs(o, now, hl); ww < 0.19 || ww > 0.21 {
		t.Fatalf("weighted exo at half-life = %v, want ~0.2", ww)
	}
	// Старые записи без src (формат автопилота) читаются как own с полным доверием.
	old := NormalizeObs(NetObservation{TS: now.Format(time.RFC3339)})
	if old.Src != SrcOwn || old.Trust != TrustOwn {
		t.Fatalf("legacy row normalize: %+v", old)
	}
}

func TestAppendObservationsDedupAndReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "netprofile.jsonl")
	a := NetObservation{TS: "2026-08-28T10:00:00Z", Src: SrcOwn, HasDPI: true}
	b := NetObservation{TS: "2026-08-28T10:01:00Z", UID: "ooni:u1", Src: SrcExo}
	n, err := AppendObservations(path, []NetObservation{a, b}, 1<<20, 256)
	if err != nil || n != 2 {
		t.Fatalf("append n=%d err=%v", n, err)
	}
	// Повторный прогон пуллера с тем же UID не плодит копии.
	n, err = AppendObservations(path, []NetObservation{b}, 1<<20, 256)
	if err != nil || n != 0 {
		t.Fatalf("re-append n=%d err=%v, want 0", n, err)
	}
	obs, err := LoadObservations(path)
	if err != nil || len(obs) != 2 {
		t.Fatalf("load %d err=%v", len(obs), err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("perm %v, want 0600", st.Mode().Perm())
	}
}
