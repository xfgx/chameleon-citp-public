package chameleon

// cf_model.go — Этап F1: каноническая модель цензора («секрет среды»).
//
// Расписание эпох (DeriveSchedule, cf_schedule.go) выводится из
// DRBG(secret ‖ modelHash ‖ epoch), поэтому БАЙТЫ модели обязаны совпадать
// на ноде и у клиента. Встроенная модель v1 — каноническая заглушка:
// она фиксирует формат/версию и НЕ содержит реальных запрещённых SNI или
// сигнатур (сквозное правило safe-by-default).
//
// Эволюция модели: автопилот клиента накапливает наблюдения сети в
// data/netprofile.jsonl (F1). Замена встроенной модели на наблюденную
// произойдёт через рассылку обновления модели по борду (отдельный тип
// управляющего сообщения) — до этого момента обе стороны используют
// CanonicalCensorModelV1 и потому синхронны по определению.

// CanonicalCensorModelV1 — встроенная каноническая модель цензора.
// Детерминированная константа: любая правка меняет хэш и, значит, все
// расписания — версионируйте через поле "v" и не правьте задним числом.
const CanonicalCensorModelV1 = `{"kind":"citp-censor-model","v":1,"verdicts":["rst","timeout","blockpage_403","redirect"],"rst_window_ms":[0,1500],"blockpage_marks":["generic-403","isp-redirect"],"epoch_len_sec":3600,"safe_by_default":true}`

// DefaultScheduleModelHash — ModelHash встроенной канонической модели.
// Используется обеими сторонами, пока обновление модели не пришло по борду.
func DefaultScheduleModelHash() []byte { return ModelHash([]byte(CanonicalCensorModelV1)) }
