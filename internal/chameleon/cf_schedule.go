package chameleon

// cf_schedule.go — Этап F: ТСПУ как общий оракул и генератор расписания.
//
// Обе стороны предсказывают поведение цензора одинаково: расписание окон и
// порядок каналов выводятся из DRBG(сессионный секрет ‖ хэш модели ‖ эпоха)
// без каких-либо переговоров по сети. Модель цензора (профили сети,
// data/netprofile.json у автопилота) — «секрет среды»: одинаковая модель на
// обеих сторонах даёт одинаковое расписание, разная — разное.
//
// F3: управляющие сообщения привязываются к эпохам (BindEpoch/CheckEpoch) —
// защита от replay по времени.

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sort"
	"time"
)

// cfScheduleLabel — метка DRBG-потока расписания (domain separation).
const cfScheduleLabel = "cf-schedule-v1"

// scheduleChannels — каналы, участвующие в перестановке расписания.
var scheduleChannels = []string{"board", "dns", "car", "ct"}

// ErrEpochOutOfWindow — сообщение привязано к эпохе вне допустимого окна
// (replay старой эпохи или сообщение из будущего).
var ErrEpochOutOfWindow = errors.New("cf-schedule: message epoch outside tolerance window")

// ErrEpochMalformed — сообщение без корректного префикса эпохи.
var ErrEpochMalformed = errors.New("cf-schedule: malformed epoch-bound message")

// ModelHash — «секрет среды»: SHA-256 накопленной модели правил цензора.
// Модель должна сериализоваться детерминированно (канонический JSON):
// одинаковая сеть -> одинаковый хэш на обеих сторонах.
func ModelHash(model []byte) []byte {
	sum := sha256.Sum256(model)
	return sum[:]
}

// EpochAt — номер эпохи для момента t при длине эпохи epochLen.
func EpochAt(t time.Time, epochLen time.Duration) uint64 {
	if epochLen <= 0 {
		epochLen = time.Hour
	}
	return uint64(t.Unix()) / uint64(epochLen/time.Second)
}

// Schedule — расписание одной эпохи: обе стороны выводят его независимо.
type Schedule struct {
	Epoch uint64
	// ChannelOrder — порядок опроса каналов в этой эпохе (перестановка
	// board/dns/car/ct): нет постоянного «первый всегда board» паттерна.
	ChannelOrder []string
	// CARWindowOffset — смещение стартового окна CAR-кадра в кодовой книге
	// этой эпохи.
	CARWindowOffset int
	// BoardPollAt — моменты опроса борда внутри эпохи (от начала эпохи).
	BoardPollAt []time.Duration
	// SymbolPerm — перестановка порядка передачи символов (окон) кадра.
	SymbolPerm []int
}

// DeriveSchedule выводит расписание эпохи из DRBG(sha256(secret‖modelHash‖epoch)).
// Детерминировано: стороны с одинаковыми входами получают идентичное
// расписание (критерий этапа F — 100% совпадение на симуляторе).
func DeriveSchedule(secret, modelHash []byte, epoch uint64, epochLen time.Duration) *Schedule {
	if epochLen <= 0 {
		epochLen = time.Hour
	}
	var eb [8]byte
	binary.BigEndian.PutUint64(eb[:], epoch)
	h := sha256.New()
	h.Write(secret)
	h.Write(modelHash)
	h.Write(eb[:])
	d := NewDRBG(h.Sum(nil), cfScheduleLabel)

	// 1) Порядок каналов — Fisher-Yates поверх DRBG.
	channels := append([]string(nil), scheduleChannels...)
	for i := len(channels) - 1; i > 0; i-- {
		j := d.Intn(i + 1)
		channels[i], channels[j] = channels[j], channels[i]
	}

	// 2) Смещение окна CAR.
	offset := d.Intn(256)

	// 3) Моменты опроса борда: 2-3 точки внутри эпохи, отсортированные.
	polls := 2 + d.Intn(2)
	pollAt := make([]time.Duration, polls)
	for i := range pollAt {
		pollAt[i] = time.Duration(d.Uint64() % uint64(epochLen))
	}
	sort.Slice(pollAt, func(i, j int) bool { return pollAt[i] < pollAt[j] })

	// 4) Перестановка порядка символов (64 окна заголовок+старт кадра).
	perm := make([]int, 64)
	for i := range perm {
		perm[i] = i
	}
	for i := len(perm) - 1; i > 0; i-- {
		j := d.Intn(i + 1)
		perm[i], perm[j] = perm[j], perm[i]
	}

	return &Schedule{
		Epoch:           epoch,
		ChannelOrder:    channels,
		CARWindowOffset: offset,
		BoardPollAt:     pollAt,
		SymbolPerm:      perm,
	}
}

// DeriveScheduleAt — расписание эпохи, содержащей момент t.
func DeriveScheduleAt(secret, modelHash []byte, t time.Time, epochLen time.Duration) *Schedule {
	return DeriveSchedule(secret, modelHash, EpochAt(t, epochLen), epochLen)
}

// BindEpoch привязывает управляющее сообщение к эпохе: [epoch:8 BE][msg].
func BindEpoch(msg []byte, epoch uint64) []byte {
	out := make([]byte, 8+len(msg))
	binary.BigEndian.PutUint64(out, epoch)
	copy(out[8:], msg)
	return out
}

// CheckEpoch проверяет привязку сообщения к эпохе и возвращает полезную
// часть и эпоху. Сообщение принимается только если его эпоха в окне
// [current-tolerance, current+tolerance] — replay старых эпох отбрасывается.
func CheckEpoch(data []byte, current, tolerance uint64) ([]byte, uint64, error) {
	if len(data) < 8 {
		return nil, 0, ErrEpochMalformed
	}
	epoch := binary.BigEndian.Uint64(data[:8])
	diff := uint64(0)
	if epoch > current {
		diff = epoch - current
	} else {
		diff = current - epoch
	}
	if diff > tolerance {
		return nil, epoch, ErrEpochOutOfWindow
	}
	out := make([]byte, len(data)-8)
	copy(out, data[8:])
	return out, epoch, nil
}
