// Package chaossync реализует транспорт на синхронизации нестационарного
// ключевого хаотического потока (chaos-sync transport).
//
// Сеть здесь — не передача дискретных символов, а синхронизация двух
// хаотических осцилляторов (клиент ↔ нода). По проводу идёт только
// квантованный скалярный связующий сигнал y_wire; информация кодируется
// малыми возмущениями динамики и извлекается из ошибки синхронизации.
// Векторное поле f_k нестационарно: семейство {f_k} и расписание мутаций
// выводятся из мастер-ключа (см. schedule.go), поэтому окно наблюдения,
// достаточное для реконструкции аттрактора (Short 1994, Pérez–Cerdeira 1995),
// обесценивается быстрее, чем атакующий его набирает.
//
// Сквозное требование ядра: ПОБИТОВЫЙ детерминизм на Windows и Linux.
// Поэтому вся динамика — целочисленная арифметика Q16.48 (этот файл),
// без единой операции с плавающей точкой, без map-итераций и без
// зависимости от порядка вычислений, отличного на разных платформах.
// Целочисленное переполнение int64 в Go детерминировано спецификацией
// (оборачивание по модулю 2^64), чем ядро и пользуется.
package chaossync

import (
	"math/bits"
	"strconv"
	"strings"
)

// Fxp — знаковое число с фиксированной точкой Q16.48, хранимое в int64.
// Диапазон ≈ (-32768, 32768), разрешение 2^-48.
type Fxp int64

// FracBits — число дробных разрядов Q16.48.
const FracBits = 48

const oneRaw = int64(1) << FracBits

// One — константа 1.0 в Q16.48.
const One = Fxp(oneRaw)

// FromInt переводит целое в Fxp.
func FromInt(v int64) Fxp { return Fxp(v << FracBits) }

// FromRaw оборачивает сырое Q16.48-представление.
func FromRaw(r int64) Fxp { return Fxp(r) }

// Raw возвращает сырое Q16.48-представление.
func (a Fxp) Raw() int64 { return int64(a) }

// Add — сложение (оборачивание по модулю 2^64, детерминировано).
func (a Fxp) Add(b Fxp) Fxp { return a + b }

// Sub — вычитание (оборачивание по модулю 2^64, детерминировано).
func (a Fxp) Sub(b Fxp) Fxp { return a - b }

// Abs — модуль.
func (a Fxp) Abs() Fxp {
	if a < 0 {
		return -a
	}
	return a
}

// Mul — умножение Q16.48 через 128-битное произведение (math/bits).
// Результат — младшие 64 бита (a*b) >> 48 (арифметический сдвиг 128-битного
// двоичного дополнения). Идентичен на всех платформах.
//
// ВАЖНО: bits.Mul64(uint64(a), uint64(b)) даёт беззнаковое произведение
// двоичных дополнений — его младшие 64 бита совпадают со знаковым
// произведением, а СТАРШЕЕ слово требует коррекции знака:
//
//	ab ≡ (a mod 2^64)(b mod 2^64) − 2^64·(a·[b<0] + b·[a<0])  (mod 2^128)
//
// Без этой коррекции отрицательные операнды дают мусор в hi (найдено
// диагностическим прогоном 2026-08-30: состояние улетало из [0,1]).
func (a Fxp) Mul(b Fxp) Fxp {
	hi, lo := bits.Mul64(uint64(a), uint64(b))
	if a < 0 {
		hi -= uint64(b)
	}
	if b < 0 {
		hi -= uint64(a)
	}
	return Fxp((lo >> FracBits) | (hi << (64 - FracBits)))
}

// FromDecimal парсит десятичную строку ("0.85", "-3", ".5") в Fxp строго
// целочисленно (детерминировано). До 9 знаков после точки, |целая часть| < 2^19.
func FromDecimal(s string) (Fxp, error) {
	s = strings.TrimSpace(s)
	neg := false
	if strings.HasPrefix(s, "-") {
		neg = true
		s = strings.TrimPrefix(s, "-")
	}
	ip, fp, dot := strings.Cut(s, ".")
	var ipart int64
	var err error
	if ip != "" {
		ipart, err = strconv.ParseInt(ip, 10, 20)
		if err != nil {
			return 0, err
		}
	}
	var frac uint64
	scale := uint64(1)
	if dot && fp != "" {
		if len(fp) > 9 {
			fp = fp[:9]
		}
		frac, err = strconv.ParseUint(fp, 10, 32)
		if err != nil {
			return 0, err
		}
		for i := 0; i < len(fp); i++ {
			scale *= 10
		}
	}
	// frac*2^48 / scale; hi < scale гарантировано: frac < scale ≤ 10^9,
	// hi < 10^9 * 2^48 / 2^64 = 10^9 / 2^16 < scale... проверено для n ≤ 9.
	hi, lo := bits.Mul64(frac, uint64(oneRaw))
	q, _ := bits.Div64(hi, lo, scale)
	res := (ipart << FracBits) | int64(q)
	if neg {
		res = -res
	}
	return Fxp(res), nil
}

// MustDecimal — FromDecimal с паникой при ошибке (для констант).
func MustDecimal(s string) Fxp {
	v, err := FromDecimal(s)
	if err != nil {
		panic("chaossync: bad decimal " + strconv.Quote(s) + ": " + err.Error())
	}
	return v
}
