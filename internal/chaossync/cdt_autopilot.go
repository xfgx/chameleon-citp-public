package chaossync

// cdt_autopilot.go — автопилот степени дисперсии CDT.
// Из постановки: автопилот выбирает степень дисперсии (сколько адресов/портов,
// насколько рвать тайминг) как trade-off «невидимость против накладных/латентности».
// Вход — уровень риска [0,1] (от DPI-профайлера: какая геометрия триггерит ТСПУ).
// Выход — GeomConfig. risk≈0 → узкий блок портов, длинные микро-потоки, малые
// интервалы (быстро); risk≈1 → широкий блок, частый churn, широкий разброс
// интервалов (скрытно). Честная ручка: дисперсия покупается ценой латентности.

// AutopilotGeom — степень дисперсии по уровню риска [0,1].
func AutopilotGeom(risk float64) GeomConfig {
	if risk < 0 {
		risk = 0
	}
	if risk > 1 {
		risk = 1
	}
	lerp := func(lo, hi int) int { return lo + int(float64(hi-lo)*risk+0.5) }
	return GeomConfig{
		PortBase:  20000,
		PortCount: lerp(8, 512), // шире блок портов -> больше дисперсия
		MinFrag:   48,
		MaxFrag:   1400,
		MinGapUs:  0,
		MaxGapUs:  lerp(100, 8000), // шире разброс интервалов -> медленнее, но шумоподобнее
		MinFlow:   1,
		MaxFlow:   lerp(48, 2), // короче микро-поток -> чаще churn src-порта
	}
}

// --- авто-подбор степени дисперсии (следующий шаг из CDT.md §4/§8) --------

// GeomClasses — число классов дисперсии: 0 = быстро/узко .. 3 = скрытно/широко.
const GeomClasses = 4

// Риск — максимум источников (консервативно: достаточно одного сигнала):
//
//	dpiRisk      — внешняя оценка DPI-профайлера [0,1] (0 = нет данных/чисто);
//	retxRate     — доля ретрансляций в надёжном потоке (0.25+ = риск 1);
//	rttInflation — RTT к базовой линии (RTT x3 = риск 1; 1.0 = норма).
func RiskFromMetrics(dpiRisk, retxRate, rttInflation float64) float64 {
	r := dpiRisk
	if retxRate > 0 {
		if x := retxRate * 4; x > r {
			r = x
		}
	}
	if rttInflation > 1 {
		if x := (rttInflation - 1) / 2; x > r {
			r = x
		}
	}
	if r < 0 {
		r = 0
	}
	if r > 1 {
		r = 1
	}
	return r
}

// RiskClass — квантование риска в класс дисперсии [0..GeomClasses-1].
func RiskClass(risk float64) int {
	if risk < 0 {
		risk = 0
	}
	if risk > 1 {
		risk = 1
	}
	return int(risk*float64(GeomClasses-1) + 0.5)
}

// AutopilotGeomClass — геометрия класса поверх базового конфига: PortBase/Dir/
// MinFrag/MaxFrag сохраняются (адресация и MTU — не ручки дисперсии),
// масштабируются PortCount, MaxGapUs, MaxFlow. Исключение: узкий базовый блок
// (PortCount <= 1, NAT-дыра клиента) не расширяется — дисперсия там
// намеренно асимметрична.
func AutopilotGeomClass(base GeomConfig, class int) GeomConfig {
	if class < 0 {
		class = 0
	}
	if class > GeomClasses-1 {
		class = GeomClasses - 1
	}
	g := AutopilotGeom(float64(class) / float64(GeomClasses-1))
	out := base.withDefaults()
	out.PortCount = g.PortCount
	out.MaxGapUs = g.MaxGapUs
	out.MaxFlow = g.MaxFlow
	if base.PortCount <= 1 {
		out.PortCount = base.withDefaults().PortCount
	}
	return out
}

// ClassStepper — гистерезис класса: не более ±1 за решение и удержание
// минимум dwell эпох между сменами (анти-флаппинг на шумных метриках).
// Первое наблюдение калибрует класс сразу (стартовая оценка сети).
type ClassStepper struct {
	class     int
	dwell     uint64
	lastEpoch uint64
	set       bool
}

func NewClassStepper(startClass int, dwell uint64) *ClassStepper {
	if startClass < 0 {
		startClass = 0
	}
	if startClass > GeomClasses-1 {
		startClass = GeomClasses - 1
	}
	if dwell == 0 {
		dwell = 2
	}
	return &ClassStepper{class: startClass, dwell: dwell}
}

// Class — текущий класс (до первого Step — стартовый).
func (cs *ClassStepper) Class() int { return cs.class }

// Step — новая оценка риска на границе эпохи -> (возможно новый) класс.
func (cs *ClassStepper) Step(risk float64, epoch uint64) int {
	cls := RiskClass(risk)
	if !cs.set {
		cs.class = cls
		cs.lastEpoch = epoch
		cs.set = true
		return cs.class
	}
	if cls == cs.class || epoch < cs.lastEpoch+cs.dwell {
		return cs.class
	}
	if cls > cs.class {
		cs.class++
	} else {
		cs.class--
	}
	cs.lastEpoch = epoch
	return cs.class
}
