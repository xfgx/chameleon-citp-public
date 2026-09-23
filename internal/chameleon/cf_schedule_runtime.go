package chameleon

// cf_schedule_runtime.go — подключение этапа F (ТСПУ как общий генератор
// расписания) к боевому пути Control Fabric. До этого файла DeriveSchedule
// существовал изолированно; здесь расписание эпохи начинает управлять
// реальными каналами:
//
//   - F3: каждое управляющее сообщение привязывается к эпохе (BindEpoch),
//     читатели отбрасывают сообщения вне окна ±1 эпоха (анти-replay по времени);
//   - F2: стартовое окно CAR-кадра смещается на Schedule.CARWindowOffset —
//     у наблюдателя нет стабильного «первого окна» (CARCodebook.Rotated);
//   - F2: RecoverControlAny опрашивает каналы в порядке Schedule.ChannelOrder
//     текущей эпохи, а не в фиксированном board->dns->car->ct;
//   - C3: зашифрованный чанк в DNS-маячке публикуется под эпохальной меткой
//     (DNSEpochLabel) — кэши резолверов не отдают прошлую эпоху.
//
// Синхронность сторон: секрет — SessionSecret (общий по cf_seed), модель —
// каноническая встроенная (DefaultScheduleModelHash, cf_model.go). Обе
// стороны выводят идентичное расписание без обмена данными по сети.
//
// Совместимость: фабрика без WithSchedule работает в прежнем legacy-формате
// (без привязки к эпохам). Смешение режимов несовместимо по формату —
// включение делается одновременно на ноде и клиенте (см. -cf-schedule).

import (
	"errors"
	"time"
)

// DefaultScheduleEpochLen — длина эпохи расписания по умолчанию. CAR-кадр
// идёт ~10-20 минут, эпоха заведомо длиннее кадра.
const DefaultScheduleEpochLen = time.Hour

// scheduleEpochTolerance — допуск CheckEpoch в эпохах: сообщение принимается
// в текущей, предыдущей и следующей эпохе (граница эпох в середине передачи).
const scheduleEpochTolerance uint64 = 1

// scheduleConfig — конфигурация этапа F для фабрики.
type scheduleConfig struct {
	modelHash []byte
	epochLen  time.Duration
}

// WithSchedule включает этап F для фабрики. Пустой modelHash = каноническая
// модель v1 (DefaultScheduleModelHash); epochLen <= 0 = DefaultScheduleEpochLen.
func (cf *ControlFabric) WithSchedule(modelHash []byte, epochLen time.Duration) *ControlFabric {
	if len(modelHash) == 0 {
		modelHash = DefaultScheduleModelHash()
	}
	if epochLen <= 0 {
		epochLen = DefaultScheduleEpochLen
	}
	cf.mu.Lock()
	defer cf.mu.Unlock()
	cf.sched = &scheduleConfig{modelHash: modelHash, epochLen: epochLen}
	return cf
}

// ScheduleEnabled сообщает, включён ли этап F.
func (cf *ControlFabric) ScheduleEnabled() bool {
	cf.mu.Lock()
	defer cf.mu.Unlock()
	return cf.sched != nil
}

// ScheduleEpochLen — настроенная длина эпохи (DefaultScheduleEpochLen, если
// этап F выключен).
func (cf *ControlFabric) ScheduleEpochLen() time.Duration {
	cf.mu.Lock()
	defer cf.mu.Unlock()
	if cf.sched == nil {
		return DefaultScheduleEpochLen
	}
	return cf.sched.epochLen
}

// scheduleNow — конфиг и расписание эпохи для момента t (nil, если этап F выключен).
func (cf *ControlFabric) scheduleNow(t time.Time) (*scheduleConfig, *Schedule) {
	cf.mu.Lock()
	s := cf.sched
	cf.mu.Unlock()
	if s == nil {
		return nil, nil
	}
	return s, DeriveScheduleAt(cf.SessionSecret(), s.modelHash, t, s.epochLen)
}

// CurrentSchedule возвращает расписание эпохи для момента t (nil, если этап F
// выключен). Клиент использует его для планового опроса борда в точках
// Schedule.BoardPollAt вместо фиксированного таймера.
func (cf *ControlFabric) CurrentSchedule(t time.Time) *Schedule {
	_, s := cf.scheduleNow(t)
	return s
}

// bindMessage привязывает сообщение к эпохе момента t (F3).
func (cf *ControlFabric) bindMessage(msg []byte, t time.Time) []byte {
	_, sched := cf.scheduleNow(t)
	if sched == nil {
		return msg
	}
	return BindEpoch(msg, sched.Epoch)
}

// unbindMessage проверяет привязку к эпохе (окно ±scheduleEpochTolerance) и
// возвращает полезную часть. Replay сообщений старых эпох отбрасывается.
func (cf *ControlFabric) unbindMessage(msg []byte, t time.Time) ([]byte, error) {
	s, sched := cf.scheduleNow(t)
	if sched == nil {
		return msg, nil
	}
	cur := EpochAt(t, s.epochLen)
	out, _, err := CheckEpoch(msg, cur, scheduleEpochTolerance)
	return out, err
}

// carCodebook — кодовая книга CAR со смещением стартового окна из расписания
// эпохи (F2). То же смещение выводит и вторая сторона.
func (cf *ControlFabric) carCodebook(key []byte, t time.Time) *CARCodebook {
	book := NewCARCodebookForPayload(key, CARMaxPayload, CARFrameRep)
	_, sched := cf.scheduleNow(t)
	if sched == nil {
		return book
	}
	return book.Rotated(sched.CARWindowOffset)
}

// channelOrder — порядок опроса каналов в RecoverControlAny: перестановка из
// расписания эпохи (F2) либо фиксированный legacy-порядок.
func (cf *ControlFabric) channelOrder(t time.Time) []string {
	_, sched := cf.scheduleNow(t)
	if sched == nil {
		return []string{"board", "dns", "car", "ct"}
	}
	return sched.ChannelOrder
}

// recoverDNS читает зашифрованный чанк сообщения из DNS-маячка. При включённом
// этапе F чанк живёт под эпохальной меткой (C3): пробуем текущую и соседние
// эпохи (публикация могла случиться на границе).
func (cf *ControlFabric) recoverDNS(r *DNSBeaconReader, now time.Time) ([]byte, error) {
	key := cf.SessionSecret()
	s, sched := cf.scheduleNow(now)
	if sched == nil {
		chunk, err := r.ReadChunk(1)
		if err != nil {
			return nil, err
		}
		if len(chunk) == 0 {
			return nil, errors.New("control-fabric: пустой dns-чанк")
		}
		return AEADDecrypt(key, chunk)
	}
	cur := EpochAt(now, s.epochLen)
	epochs := []uint64{cur, cur + 1}
	if cur > 0 {
		epochs = append(epochs, cur-1)
	}
	var lastErr error = errors.New("control-fabric: dns: ни одна эпохальная метка не ответила")
	for _, e := range epochs {
		chunk, err := r.ReadChunkEpoch(1, e)
		if err != nil || len(chunk) == 0 {
			continue
		}
		dec, err := AEADDecrypt(key, chunk)
		if err != nil {
			lastErr = err
			continue
		}
		if m, err := cf.unbindMessage(dec, now); err == nil {
			return m, nil
		} else {
			lastErr = err
		}
	}
	return nil, lastErr
}
