package chaossync

// cdt_geomauto_test.go — автопилот дисперсии CDT: оценка риска, классы с
// гистерезисом, in-band переключение класса геометрии на границе эпохи
// (lockstep обеих сторон по надёжному потоку).

import (
	"bytes"
	"testing"
	"time"
)

// --- юниты чистых функций ---

func TestRiskFromMetrics(t *testing.T) {
	if r := RiskFromMetrics(0, 0, 1.0); r != 0 {
		t.Fatalf("чистые метрики: risk=%v", r)
	}
	if r := RiskFromMetrics(0.4, 0.01, 1.1); r < 0.39 || r > 0.41 {
		t.Fatalf("max-семантика: risk=%v, ждём ~0.4", r)
	}
	if r := RiskFromMetrics(0, 0.5, 1.0); r != 1 {
		t.Fatalf("retx 0.5 -> risk=1, got %v", r)
	}
	if r := RiskFromMetrics(0, 0, 3.0); r != 1 {
		t.Fatalf("rtt x3 -> risk=1, got %v", r)
	}
	if r := RiskFromMetrics(2, 9, 9); r != 1 {
		t.Fatalf("кламп сверху: %v", r)
	}
	if r := RiskFromMetrics(-1, -1, 0); r != 0 {
		t.Fatalf("кламп снизу: %v", r)
	}
}

func TestRiskClassAndGeom(t *testing.T) {
	if RiskClass(0) != 0 || RiskClass(1) != GeomClasses-1 {
		t.Fatal("границы классов")
	}
	base := GeomConfig{PortBase: 20000, PortCount: 48, MinFrag: 200, MaxFrag: 1400, Dir: "c2n"}
	g0 := AutopilotGeomClass(base, 0)
	g3 := AutopilotGeomClass(base, 3)
	if g0.Dir != "c2n" || g3.Dir != "c2n" || g0.PortBase != 20000 {
		t.Fatal("класс обязан сохранять Dir/PortBase")
	}
	if g0.PortCount >= g3.PortCount {
		t.Fatalf("PortCount не растёт с классом: %d vs %d", g0.PortCount, g3.PortCount)
	}
	if g3.MaxGapUs <= g0.MaxGapUs {
		t.Fatal("MaxGapUs не растёт с классом")
	}
	if g3.MaxFlow >= g0.MaxFlow {
		t.Fatal("MaxFlow не падает с классом (чаще churn)")
	}
	// узкий базовый блок (NAT-дыра клиента) не расширяется
	n2c := GeomConfig{PortBase: 23500, PortCount: 1, Dir: "n2c"}
	if AutopilotGeomClass(n2c, 3).PortCount != 1 {
		t.Fatal("NAT-дыра не должна расширяться")
	}
}

func TestClassStepper(t *testing.T) {
	cs := NewClassStepper(0, 2)
	if cs.Step(1.0, 100) != 3 {
		t.Fatal("первое наблюдение калибрует сразу")
	}
	if cs.Step(0.0, 101) != 3 {
		t.Fatal("dwell: смена запрещена раньше dwell эпох")
	}
	if cs.Step(0.0, 102) != 2 {
		t.Fatal("после dwell — шаг вниз на 1")
	}
	if cs.Step(0.0, 103) != 2 {
		t.Fatal("dwell после смены")
	}
	if cs.Step(0.0, 104) != 1 {
		t.Fatal("второй шаг вниз")
	}
	if NewClassStepper(99, 0).Class() != GeomClasses-1 {
		t.Fatal("кламп стартового класса")
	}
}

// --- сквозной lockstep переключения класса ---

// geoLink — две стороны потока с очередями доставки и общими фиктивными часами.
type geoLink struct {
	a, b   *Stream
	aq, bq [][]byte // aq: провод a->b; bq: b->a
	now    time.Time
}

func testC2N() GeomConfig {
	return GeomConfig{PortBase: 20000, PortCount: 48, MinFrag: 200, MaxFrag: 1400, MaxGapUs: 100, MinFlow: 1, MaxFlow: 12, Dir: "c2n"}
}

func testN2C() GeomConfig {
	return GeomConfig{PortBase: 23500, PortCount: 1, MinFrag: 200, MaxFrag: 1400, MaxGapUs: 100, MinFlow: 1, MaxFlow: 12, Dir: "n2c"}
}

func newGeoLink(T uint64) *geoLink {
	master := bytes.Repeat([]byte{0x77}, 32)
	l := &geoLink{now: time.Now()}
	l.a = NewStream(master, testC2N(), testN2C(), T, func(w []byte, g PacketGeom) { l.aq = append(l.aq, w) })
	l.b = NewStream(master, testN2C(), testC2N(), T, func(w []byte, g PacketGeom) { l.bq = append(l.bq, w) })
	l.a.now = func() time.Time { return l.now }
	l.b.now = func() time.Time { return l.now }
	return l
}

func (l *geoLink) pump() {
	for len(l.aq) > 0 || len(l.bq) > 0 {
		for len(l.aq) > 0 {
			w := l.aq[0]
			l.aq = l.aq[1:]
			l.b.HandlePacket(w)
		}
		for len(l.bq) > 0 {
			w := l.bq[0]
			l.bq = l.bq[1:]
			l.a.HandlePacket(w)
		}
	}
}

func (l *geoLink) tick() {
	l.a.Tick()
	l.b.Tick()
	l.pump()
}

// Счастливый путь: риск -> класс 3, REQ/ACK по потоку, переключение на
// границе fromEpoch, данные ходят по НОВОЙ геометрии (lockstep доказан
// самим фактом сборки: несовпавшая геометрия = fail-closed отброс).
func TestStreamGeomAutoSwitch(t *testing.T) {
	l := newGeoLink(8)
	l.a.EnableGeomAutopilot(NewClassStepper(0, 2), testC2N(), testN2C())
	l.b.EnableGeomAutopilot(NewClassStepper(0, 2), testN2C(), testC2N())

	l.a.SetExtRisk(1) // поле/DPI: высокий риск
	l.tick()
	if l.a.swOut == nil {
		t.Fatal("REQ не оформлен")
	}
	if !l.a.swOut.committed {
		t.Fatal("REQ не подтверждён peer'ом")
	}
	target := l.a.swOut.fromEpoch
	for EpochFor(l.now, 8) < target {
		l.now = l.now.Add(2 * time.Second)
		l.tick()
	}
	if l.a.txClass != 3 || l.b.rxClass != 3 {
		t.Fatalf("lockstep сломан: a.tx=%d b.rx=%d", l.a.txClass, l.b.rxClass)
	}
	if l.b.txClass != 0 || l.a.rxClass != 0 {
		t.Fatal("обратное направление не должно меняться")
	}
	msg := bytes.Repeat([]byte{0x5A}, 10000)
	l.a.Write(msg)
	l.tick()
	l.tick()
	var got []byte
	for {
		p := l.b.Read()
		if p == nil {
			break
		}
		got = append(got, p...)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("payload после переключения: got %d want %d", len(got), len(msg))
	}
}

// Потеря первого REQ (проглочен после stream-ACK): переключение обязано
// переоформиться с новым fromEpoch и всё равно сойтись, без рассинхрона.
func TestStreamGeomAutoReqLost(t *testing.T) {
	l := newGeoLink(8)
	l.a.EnableGeomAutopilot(NewClassStepper(0, 2), testC2N(), testN2C())
	l.b.EnableGeomAutopilot(NewClassStepper(0, 2), testN2C(), testC2N())

	l.a.SetExtRisk(1)
	swallow := true
	l.b.ctlHookForTest = func(p []byte) bool {
		if swallow {
			swallow = false
			return true // первый REQ потерян по пути (seq поглощён, geom-ACK нет)
		}
		return false
	}
	l.tick()
	if l.a.swOut == nil || l.a.swOut.committed {
		t.Fatal("REQ должен был потеряться без подтверждения")
	}
	ok := false
	for guard := 0; guard < 60; guard++ {
		l.now = l.now.Add(2 * time.Second)
		l.tick()
		if l.a.txClass == 3 && l.b.rxClass == 3 {
			ok = true
			break
		}
	}
	if !ok {
		t.Fatalf("не сошлись после потери REQ: a.tx=%d b.rx=%d", l.a.txClass, l.b.rxClass)
	}
	msg := []byte("after-loss-lockstep-check")
	l.a.Write(msg)
	l.tick()
	l.tick()
	var got []byte
	for {
		p := l.b.Read()
		if p == nil {
			break
		}
		got = append(got, p...)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("payload не дошёл после восстановления переключения")
	}
}
