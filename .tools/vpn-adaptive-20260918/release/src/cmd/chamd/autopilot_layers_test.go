package main

// autopilot_layers_test.go — тесты обвязки слоёв 6/7/8 в автопилоте chamd.

import (
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"chameleon/internal/chameleon"
)

func newLayersTestManager(t *testing.T) *Manager {
	t.Helper()
	store, err := LoadStore(filepath.Join(t.TempDir(), "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	return NewManager(store, 5*time.Second, 0, "auto", "", nil)
}

// Слой 7: exo-пулл пишет записи src=exo в netprofile.jsonl (mock OONI).
func TestSyncExogenous(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"metadata": map[string]any{"count": 3},
			"results": []map[string]any{
				{"measurement_uid": "x1", "probe_cc": "RU", "probe_asn": "AS1", "test_name": "web_connectivity", "measurement_start_time": "2026-08-28 22:00:00", "confirmed": true},
				{"measurement_uid": "x2", "probe_cc": "RU", "test_name": "web_connectivity", "measurement_start_time": "2026-08-28 22:01:00"},
				{"measurement_uid": "x3", "probe_cc": "RU", "test_name": "web_connectivity", "failure": true},
			},
		})
	}))
	defer srv.Close()

	ap := NewAutopilot(newLayersTestManager(t), nil)
	dir := t.TempDir()
	ap.SetDataDir(dir)
	ap.SetExo(true, srv.URL)
	ap.syncExogenous("тест")

	obs, err := chameleon.LoadObservations(filepath.Join(dir, "netprofile.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 2 {
		t.Fatalf("obs %d, want 2 (failure отброшен)", len(obs))
	}
	for _, o := range obs {
		if o.Src != chameleon.SrcExo {
			t.Fatalf("src=%q, want exo", o.Src)
		}
	}
	// Повторный пулл не плодит дублей по UID.
	ap.syncExogenous("тест-2")
	obs, _ = chameleon.LoadObservations(filepath.Join(dir, "netprofile.jsonl"))
	if len(obs) != 2 {
		t.Fatalf("после повтора obs %d, want 2", len(obs))
	}
}

// Слой 8: θ от борда сохраняется, rotateStrategyFor выводит геном из набора
// кандидатов эпохи (best-of-K по fitness) и применяет его в Manager; без θ —
// legacy ротация по списку flavor'ов.
func TestThetaFromBoardAndRotate(t *testing.T) {
	m := newLayersTestManager(t)
	ap := NewAutopilot(m, nil)
	th := chameleon.DefaultTheta()
	b, err := chameleon.EncodeTheta(th)
	if err != nil {
		t.Fatal(err)
	}
	ap.handleBoardMessage(chameleon.ThetaKind, b)

	entry := ServerEntry{Name: "n1", Addr: "203.0.113.1:9443", PubKey: "x", CFSeed: "seed"}
	desc := ap.rotateStrategyFor(entry, true)
	if !strings.HasPrefix(desc, "θ-геном") {
		t.Fatalf("desc=%q, want θ-геном", desc)
	}
	f := m.flavor() // геном применён и имеет приоритет
	base := int(f.Base / time.Millisecond)
	if base < th.BaseMsLo || base > th.BaseMsHi {
		t.Fatalf("base %d вне θ", base)
	}
	if f.MaxPad < f.MinPad+100 {
		t.Fatalf("pad %d..%d", f.MinPad, f.MaxPad)
	}
	// Применённый геном обязан быть одним из K кандидатов эпохи (базовый
	// DeriveGenome + 7 солёных вариантов client‖round‖i) — выбор по fitness.
	epoch := ap.lastGenome.Epoch
	seed := []byte("chameleon-control-fabric:" + entry.CFSeed)
	pub := binary.BigEndian.AppendUint64(m.ClientPubBytes(), 0)
	found := false
	for i := -1; i < 7; i++ {
		id := pub
		if i >= 0 {
			id = append(append([]byte(nil), pub...), byte(i))
		}
		if chameleon.DeriveGenome(th, seed, epoch, id).Flavor == f {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("геном менеджера %+v не из набора кандидатов эпохи", f)
	}

	// Без θ — legacy ротация по списку flavor'ов.
	ap2 := NewAutopilot(newLayersTestManager(t), nil)
	ap2.theta = nil
	if desc2 := ap2.rotateStrategyFor(entry, true); !strings.HasPrefix(desc2, "flavor ") {
		t.Fatalf("fallback desc=%q", desc2)
	}
}

// Карта дорогих зон и неизвестные типы разбираются без паники.
func TestHandleBoardCollateral(t *testing.T) {
	ap := NewAutopilot(newLayersTestManager(t), nil)
	cm := chameleon.NewCollateralMap("AS12345", nil)
	b, err := chameleon.EncodeCollateralMap(cm)
	if err != nil {
		t.Fatal(err)
	}
	ap.handleBoardMessage(chameleon.CollateralKind, b)
	ap.handleBoardMessage("citp-unknown", []byte(`{"kind":"citp-unknown"}`))
}

// Классификатор: node-hint проходит мимо новых типов (обратная совместимость).
func TestBoardKindCompat(t *testing.T) {
	hint := []byte(`{"node_ip":"203.0.113.1","pc_ip_mode":"auto-from-client-socket"}`)
	if k := chameleon.ControlMessageKind(hint); k != "node-hint" {
		t.Fatalf("hint kind=%q", k)
	}
}
