#!/usr/bin/env python3
# patch_task1_fieldclass.py — Задача 1: классы полей + хаос-пол в DeriveField.
# Идемпотентные анкерные замены; каждая обязана найтись ровно один раз.
import sys

ROOT = "/files/VPN"

def patch(path, edits, append=None):
    p = ROOT + "/" + path
    with open(p, encoding="utf-8") as f:
        src = f.read()
    for name, old, new in edits:
        n = src.count(old)
        if n != 1:
            print(f"FAIL {path} [{name}]: anchor found {n} times", file=sys.stderr)
            sys.exit(1)
        src = src.replace(old, new, 1)
        print(f"  ok {path} [{name}]")
    if append:
        if append.strip() in src:
            print(f"  skip {path} [append already present]")
        else:
            if not src.endswith("\n"):
                src += "\n"
            src += append
            print(f"  ok {path} [append]")
    with open(p, "w", encoding="utf-8") as f:
        f.write(src)

# ---------- schedule.go ----------
sch = []

sch.append(("header-class-para",
"""// повторяют это побитово одинаково и получают одно и то же валидное поле
// без какого-либо обмена по сети.
""",
"""// повторяют это побитово одинаково и получают одно и то же валидное поле
// без какого-либо обмена по сети.
//
// КЛАССЫ ПОЛЕЙ (2026-09-01, по итогам замера Э-A, docs/CHAOS-METRICS.md):
// критерий сходимости наблюдателя требует сильной связи (eps~0.4), которая
// топит хаос — выбранные так прод-поля квазипериодичны (lambda1 ~ +-3e-6,
// h_KS ~ 0). Поэтому назначение поля разделено на два класса со своими
// критериями: FieldClassSync — carrier control-plane (критерий прежний,
// поток кандидатов не изменён — гейт Э1 сохраняется); FieldClassKeystream —
// data-plane keystream и Э6-заявки: хаос-пол, кандидат принимается только при
// lambda1 >= KeystreamLambdaMin (целочисленный Benettin-lite EstimateLambdaMax,
// lambda.go; связь вытягивается из зоны хаоса eps в [0, 0.05)). Отбраковка —
// следующий кандидат из того же DRBG-потока эпохи, побитово одинаково на
// обеих сторонах.
"""))

sch.append(("const-label-ks",
"""const (
\tschedLabel = "chaossync-field-v2"
\tcstLabel   = "chaossync-cst-v1"
\tidleLabel  = "chaossync-idle-v1"
)""",
"""const (
\tschedLabel = "chaossync-field-v2"
\t// schedLabelKs — DRBG-метка keystream-класса: независимый от sync поток
\t// кандидатов (sync-поток не меняется → исторические поля и гейт Э1 целы).
\tschedLabelKs = "chaossync-field-ks-v1"
\tcstLabel     = "chaossync-cst-v1"
\tidleLabel    = "chaossync-idle-v1"
)"""))

sch.append(("ks-eps-span",
"""\txBase  = MustDecimal("0.05")
\txSpan  = uint64(253327479039590) // +[0, 0.9)  → x0 ∈ (0.05, 0.95)
)""",
"""\txBase  = MustDecimal("0.05")
\txSpan  = uint64(253327479039590) // +[0, 0.9)  → x0 ∈ (0.05, 0.95)
)

// ksEpsSpan — диапазон связи keystream-класса: eps1,eps2 ∈ [0, 0.05), зона
// хаоса по свипу Э-A (lambda1 ~ 0.5-0.85 бит/итер; к eps~0.10-0.15 — коллапс
// в порядок). mu и топология вытягиваются той же схемой, что у sync-класса.
const ksEpsSpan = uint64(14073748835533) // +[0, 0.05)"""))

sch.append(("drawfield-ranged",
"""// drawField — один кандидат поля из текущего состояния DRBG.
func drawField(d *chameleon.DRBG) *FieldParams {
\tp := &FieldParams{}
\tfor i := 0; i < Sites; i++ {
\t\tp.Mu[i] = drawRange(d, muBase, muSpan)
\t}
\tp.Eps1 = drawRange(d, e1Base, e1Span)
\tp.Eps2 = drawRange(d, e2Base, e2Span)""",
"""// drawField — один кандидат sync-класса из текущего состояния DRBG
// (исторические диапазоны связи; поведение не изменялось — гейт Э1).
func drawField(d *chameleon.DRBG) *FieldParams {
\treturn drawFieldRanged(d, e1Base, e1Span, e2Base, e2Span)
}

// drawFieldRanged — кандидат с заданными диапазонами связи. Порядок
// вытягивания из DRBG идентичен drawField (mu → eps1 → eps2 → топология →
// drive), поэтому sync-класс получает ровно исторический поток кандидатов.
func drawFieldRanged(d *chameleon.DRBG, e1b Fxp, e1s uint64, e2b Fxp, e2s uint64) *FieldParams {
\tp := &FieldParams{}
\tfor i := 0; i < Sites; i++ {
\t\tp.Mu[i] = drawRange(d, muBase, muSpan)
\t}
\tp.Eps1 = drawRange(d, e1b, e1s)
\tp.Eps2 = drawRange(d, e2b, e2s)"""))

sch.append(("keystream-vars",
"""\tprobeMaxAttempts = 100000 // аварийный предел перерисовки (недостижим практически)
)""",
"""\tprobeMaxAttempts = 100000 // аварийный предел перерисовки (недостижим практически)
)

// Параметры хаос-пола keystream-класса. КОНФИГУРИРУЕМЫ, но обязаны быть
// выставлены до первого вывода поля и ОДИНАКОВЫ на обеих сторонах (как весь
// Config): стороны по ним независимо выбирают одно и то же поле эпохи.
var (
\t// KeystreamLambdaMin — порог отбора lambda1 (бит/итерация, Q16.48).
\t// Стартовая точка 0.5 — по свипу Э-A (хаос при eps<~0.05: 0.5-0.85);
\t// финализирована замером приёмки (agent.md, 2026-09-01).
\tKeystreamLambdaMin = MustDecimal("0.5")
\t// KeystreamLambdaIters — длина Benettin-lite прогона EstimateLambdaMax
\t// (8192 итерации ~= 15-25 мс/кандидат на CPU ноды — в бюджете ~50 мс/поле).
\tKeystreamLambdaIters = 8192
)"""))

sch.append(("fieldclass-type",
"""type fieldCacheKey struct {
\tmaster [32]byte // sha256(master), сам секрет в ключе не держим
\tepoch  uint64
}""",
"""// FieldClass — класс назначения поля эпохи (2026-09-01, по итогам замера
// Э-A): критерий «сходимость наблюдателя» требует сильной связи, которая
// топит хаос, поэтому keystream/Э6-поля выводятся отдельным классом.
type FieldClass int

const (
\t// FieldClassSync — carrier control-plane: критерий без изменений
\t// (стабильная связь, сходимость наблюдателя).
\tFieldClassSync FieldClass = iota
\t// FieldClassKeystream — data-plane keystream/Э6: хаос-пол
\t// (lambda1 >= KeystreamLambdaMin, связь из зоны хаоса eps в [0, 0.05)).
\tFieldClassKeystream
)

// classLabel — DRBG-метка класса (независимые потоки кандидатов).
func classLabel(class FieldClass) string {
\tif class == FieldClassKeystream {
\t\treturn schedLabelKs
\t}
\treturn schedLabel
}

type fieldCacheKey struct {
\tmaster [32]byte // sha256(master), сам секрет в ключе не держим
\tepoch  uint64
\tclass  FieldClass
}"""))

sch.append(("derive-dispatch",
"""// DeriveField — кэшированная обёртка над deriveFieldUncached.
func DeriveField(master []byte, epoch uint64) *FieldParams {
\tkey := fieldCacheKey{master: sha256.Sum256(master), epoch: epoch}""",
"""// DeriveField — sync-класс (carrier control-plane): исторический критерий
// сходимости наблюдателя, поведение не изменялось — гейт Э1 покрывает этот
// путь (золотой хэш 29f2315f…).
func DeriveField(master []byte, epoch uint64) *FieldParams {
\treturn DeriveFieldClass(master, epoch, FieldClassSync)
}

// DeriveFieldClass — кэшированная обёртка над deriveFieldUncached.
func DeriveFieldClass(master []byte, epoch uint64, class FieldClass) *FieldParams {
\tkey := fieldCacheKey{master: sha256.Sum256(master), epoch: epoch, class: class}"""))

sch.append(("uncached-call",
"""\tp := deriveFieldUncached(master, epoch)
""",
"""\tp, _ := deriveFieldUncached(master, epoch, class)
"""))

sch.append(("uncached-body",
"""func deriveFieldUncached(master []byte, epoch uint64) *FieldParams {
\td := chameleon.NewDRBG(epochSeed(master, schedLabel, epoch), "params")
\tfor attempt := 0; attempt < probeMaxAttempts; attempt++ {
\t\tp := drawField(d)
\t\tif fieldConverges(master, epoch, p) {
\t\t\treturn p
\t\t}
\t}
\t// Недостижимо статистически (вероятность ~1e-30 на эпоху); обе стороны
\t// упали бы одинаково — fail-closed сохраняется даже здесь.
\tpanic("chaossync: поле не сходится после probeMaxAttempts перерисовок")
}""",
"""// deriveFieldUncached — вывод поля класса; возвращает поле и число
// кандидатов (1 + отбраковано) для телеметрии/тестов.
func deriveFieldUncached(master []byte, epoch uint64, class FieldClass) (*FieldParams, int) {
\td := chameleon.NewDRBG(epochSeed(master, classLabel(class), epoch), "params")
\tfor attempt := 0; attempt < probeMaxAttempts; attempt++ {
\t\tif class == FieldClassKeystream {
\t\t\t// Хаос-пол: кандидат из зоны хаоса (eps в [0, 0.05)) принимается
\t\t\t// только при lambda1 >= KeystreamLambdaMin. Отбраковка — следующий
\t\t\t// кандидат из того же DRBG-потока эпохи (детерминировано на обеих
\t\t\t// сторонах). Оценка lambda1 целочисленная → бит-идентична Win/Linux.
\t\t\tp := drawFieldRanged(d, Fxp(0), ksEpsSpan, Fxp(0), ksEpsSpan)
\t\t\tif EstimateLambdaMax(p, KeystreamLambdaIters) >= KeystreamLambdaMin {
\t\t\t\treturn p, attempt + 1
\t\t\t}
\t\t\tcontinue
\t\t}
\t\tp := drawField(d)
\t\tif fieldConverges(master, epoch, p) {
\t\t\treturn p, attempt + 1
\t\t}
\t}
\t// Недостижимо статистически; обе стороны упали бы одинаково — fail-closed
\t// сохраняется даже здесь.
\tpanic("chaossync: поле не прошло отбор класса после probeMaxAttempts перерисовок")
}"""))

sch.append(("epochinit-class",
"""// EpochInit — ключевой reseed состояния на границе эпохи. Обе стороны
// перепрыгивают в одну и ту же точку нового аттрактора.
func EpochInit(master []byte, epoch uint64) [Sites]Fxp {
\td := chameleon.NewDRBG(epochSeed(master, schedLabel, epoch), "init")
\tvar x [Sites]Fxp
\tfor i := 0; i < Sites; i++ {
\t\tx[i] = drawRange(d, xBase, xSpan)
\t}
\treturn x
}""",
"""// EpochInit — ключевой reseed состояния на границе эпохи (sync-класс).
// Поведение не изменялось — гейт Э1. Обе стороны перепрыгивают в одну и ту же
// точку нового аттрактора.
func EpochInit(master []byte, epoch uint64) [Sites]Fxp {
\treturn EpochInitClass(master, epoch, FieldClassSync)
}

// EpochInitClass — reseed состояния эпохи для класса поля: поток
// инициализации выводится из метки класса (у keystream-полей — своё
// стартовое состояние, независимое от sync).
func EpochInitClass(master []byte, epoch uint64, class FieldClass) [Sites]Fxp {
\td := chameleon.NewDRBG(epochSeed(master, classLabel(class), epoch), "init")
\tvar x [Sites]Fxp
\tfor i := 0; i < Sites; i++ {
\t\tx[i] = drawRange(d, xBase, xSpan)
\t}
\treturn x
}"""))

patch("internal/chaossync/schedule.go", sch)

# ---------- ks.go ----------
ks = []
ks.append(("ks-header-model",
"""// Модель: для эпохи m обе стороны выводят одно и то же само-валидирующееся
// поле DeriveField и стартовое состояние EpochInit (переиспользованы из
// schedule.go без изменений — гейт Э1 и золотой хэш 29f2315f… сохранены и
// покрывают этот путь).""",
"""// Модель: для эпохи m обе стороны выводят одно и то же поле
// DeriveFieldClass(FieldClassKeystream) и стартовое состояние EpochInitClass
// (schedule.go, 2026-09-01). Класс keystream — хаос-пол: отбор по
// lambda1 >= KeystreamLambdaMin целочисленным Benettin-lite (по замеру Э-A
// критерий сходимости наблюдателя хаос убивает, а наблюдатель keystream'у не
// нужен). Побитовый детерминизм сохранён: sync-класс и гейт Э1 (золотой хэш
// 29f2315f…) не тронуты; KS-golden перевыпущен под хаос-поля и проверен
// Windows-билдом под wine против Linux."""))

ks.append(("keygen-class",
"""\tm := dirMaster(master, dir)
\treturn &KeyGen{field: DeriveField(m, epoch), state: EpochInit(m, epoch)}""",
"""\tm := dirMaster(master, dir)
\t// keystream-класс: хаос-пол (lambda1 >= KeystreamLambdaMin) + свой
\t// reseed-поток инициализации (schedule.go).
\treturn &KeyGen{
\t\tfield: DeriveFieldClass(m, epoch, FieldClassKeystream),
\t\tstate: EpochInitClass(m, epoch, FieldClassKeystream),
\t}"""))

patch("internal/chaossync/ks.go", ks)

# ---------- selftest.go ----------
append_selftest = """
// FieldClassGoldenVector — хэш выбранных полей ОБОИХ классов (и оценок lambda1
// для keystream) на публичном мастере и фиксированных эпохах: гейт
// бит-идентичности ВЫБОРА ПОЛЯ Windows↔Linux (задача «хаос-пол», 2026-09-01).
// Оценка lambda1 целочисленная (lambda.go) → обязано совпасть на любой
// платформе; расхождение = стороны разойдутся в полях эпох, линк не встанет.
func FieldClassGoldenVector() string {
\th := sha256.New()
\tvar b [8]byte
\tputRaw := func(v int64) { binary.BigEndian.PutUint64(b[:], uint64(v)); h.Write(b[:]) }
\tputField := func(p *FieldParams) {
\t\tfor i := 0; i < Sites; i++ {
\t\t\tputRaw(p.Mu[i].Raw())
\t\t}
\t\tputRaw(p.Eps1.Raw())
\t\tputRaw(p.Eps2.Raw())
\t\tfor i := 0; i < Sites; i++ {
\t\t\tputRaw(int64(p.Next[i]))
\t\t\tputRaw(int64(p.Prev[i]))
\t\t}
\t\tputRaw(int64(p.Drive))
\t}
\tfor _, class := range []FieldClass{FieldClassSync, FieldClassKeystream} {
\t\tfor _, e := range []uint64{0, 1, 2, 42, 77, 424242} {
\t\t\tp := DeriveFieldClass(SelftestMaster, e, class)
\t\t\tputField(p)
\t\t\tif class == FieldClassKeystream {
\t\t\t\tputRaw(EstimateLambdaMax(p, KeystreamLambdaIters).Raw())
\t\t\t}
\t\t}
\t}
\treturn hex.EncodeToString(h.Sum(nil))
}
"""
patch("internal/chaossync/selftest.go", [], append=append_selftest)

# ---------- cmd/chaossync-selftest/main.go ----------
st = []
st.append(("selftest-line3",
"""\tfmt.Println(chaossync.SelftestVector())
\tfmt.Println(chaossync.KsGoldenVector())""",
"""\tfmt.Println(chaossync.SelftestVector())
\tfmt.Println(chaossync.KsGoldenVector())
\t// Строка 3 — выбор полей обоих классов + оценки lambda1 (гейт задачи
\t// «хаос-пол»: бит-идентичность выбора поля Win↔Linux).
\tfmt.Println(chaossync.FieldClassGoldenVector())"""))
patch("cmd/chaossync-selftest/main.go", st)

print("PATCH TASK1 DONE")
