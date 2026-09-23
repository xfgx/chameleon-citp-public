package chameleon

// cf_car_codebook.go — Этап A1: кодовая книга CAR-канала из общего секрета.
//
// Метки окон (path-токены) и порядок их передачи выводятся из DRBG на
// сессионном секрете — тот же подход, что у flavors. Обе стороны вычисляют
// книгу независимо и байт-в-байт одинаково, поэтому список путей НИКОГДА не
// передаётся по сети.
//
// Пути выглядят как /car/<10 hex-символов>: никаких последовательных
// целочисленных /car/0, /car/1, ... — эвристика "sequential seq" нашего же
// детектора verdict-probing на таком трафике молчит.
//
// SAFE BY DESIGN: метки — чистый вывод DRBG, никаких реальных запрещённых
// SNI/сигнатур в коде (roadmap, сквозное правило 3). Триггерные сигнатуры —
// конфигурация оператора ноды, не кодовая книга.

import (
	"encoding/hex"
	"strconv"
)

// carCodebookLabel — метка DRBG-потока кодовой книги (domain separation).
const carCodebookLabel = "car-codebook-v1"

// CARCodebook — детерминированная книга окон CAR-канала. Окно i на проводе —
// это Label(i); порядок окон уже перемешан при построении (Fisher-Yates на
// том же DRBG), поэтому стороны просто идут по индексам 0..n-1.
type CARCodebook struct {
	labels []string
}

// NewCARCodebook выводит книгу на windows окон из общего секрета.
// Обычно secret = ControlFabric.SessionSecret(), а windows =
// CARFrameWindows(maxPayload, rep). Число окон должно совпадать на обеих
// сторонах — это часть конфигурации канала, а не переговоры по сети.
func NewCARCodebook(secret []byte, windows int) *CARCodebook {
	if windows < 1 {
		windows = 1
	}
	d := NewDRBG(secret, carCodebookLabel)
	seen := make(map[string]struct{}, windows)
	labels := make([]string, 0, windows)
	for len(labels) < windows {
		l := hex.EncodeToString(d.Bytes(5)) // 10 hex-символов, ~40 бит энтропии
		if _, dup := seen[l]; dup {
			continue
		}
		// Чисто числовая метка выглядела бы как последовательный /car/<seq> —
		// паттерн, который ловит наш verdict-probing детектор. Пропускаем.
		if _, err := strconv.Atoi(l); err == nil {
			continue
		}
		seen[l] = struct{}{}
		labels = append(labels, l)
	}
	// Перемешивание порядка окон тем же потоком (Fisher-Yates).
	for i := len(labels) - 1; i > 0; i-- {
		j := d.Intn(i + 1)
		labels[i], labels[j] = labels[j], labels[i]
	}
	return &CARCodebook{labels: labels}
}

// NewCARCodebookForPayload — удобная обёртка: книга, достаточная для кадра с
// payload до maxPayload байт при факторе повторения rep.
func NewCARCodebookForPayload(secret []byte, maxPayload, rep int) *CARCodebook {
	return NewCARCodebook(secret, CARFrameWindows(maxPayload, rep))
}

// Windows — число окон в книге.
func (b *CARCodebook) Windows() int { return len(b.labels) }

// Label возвращает path-метку окна i (паникует при выходе за границы — это
// ошибка конфигурации, а не сетевое событие).
func (b *CARCodebook) Label(i int) string { return b.labels[i] }

// Labels возвращает копию списка меток в порядке передачи.
func (b *CARCodebook) Labels() []string {
	out := make([]string, len(b.labels))
	copy(out, b.labels)
	return out
}

// Rotated возвращает книгу с циклически сдвинутым порядком окон (этап F2):
// стартовое окно кадра смещается на n позиций по модулю числа окон. Смещение
// выводится обеими сторонами из расписания эпохи (Schedule.CARWindowOffset),
// поэтому по сети оно не передаётся, а у наблюдателя нет стабильного
// «первого окна» кадра.
func (b *CARCodebook) Rotated(n int) *CARCodebook {
	w := len(b.labels)
	if w == 0 {
		return b
	}
	n %= w
	if n < 0 {
		n += w
	}
	out := make([]string, 0, w)
	out = append(out, b.labels[n:]...)
	out = append(out, b.labels[:n]...)
	return &CARCodebook{labels: out}
}
