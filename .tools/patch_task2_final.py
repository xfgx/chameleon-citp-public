#!/usr/bin/env python3
# patch_task2_final.py — финализация M8 по замерам: plain-sum + c=0.95 для M8.
import sys
ROOT = "/files/VPN"

def patch(path, edits):
    p = ROOT + "/" + path
    src = open(p, encoding="utf-8").read()
    for name, old, new in edits:
        n = src.count(old)
        if n != 1:
            print(f"FAIL {path} [{name}]: anchor {n}", file=sys.stderr); sys.exit(1)
        src = src.replace(old, new, 1)
        print(f"  ok {path} [{name}]")
    open(p, "w", encoding="utf-8").write(src)

# ---------- modem.go: откат skip-механики -> финальный plain модем ----------
patch("internal/chaossync/modem.go", [("final-modem",
'''// Защитный интервал (Skip): первый сэмпл окна несёт межсимвольный транзиент
// — лаг наблюдателя от уровня ПРЕДЫДУЩЕГО символа (порядка (1−c)·slope·Δd —
// доминирующий шум классификатора, измерено замером 2026-09-01: без защиты
// bitBER ~7% при S=2). Он исключается из интеграла residual; пороги
// масштабируются на S−Skip интегрированных сэмплов.
type Modem8 struct {
\tS      int    // сэмплов на символьное окно
\tSkip   int    // защитные сэмплы в начале окна (в интеграл не входят)
\tLevels [8]Fxp // сдвиг драйв-сайта по индексу уровня (Грей от битов потока)
\tthr    [7]Fxp // серединные пороги классификатора, заранее ×(S−Skip)
}

// m8GuardSamples — дефолт защитного интервала M8. Финализирован замером
// (m8_test.go sweep; числа — в agent.md 2026-09-01).
const m8GuardSamples = 1

// NewModem8 — штатный модем для (δ, S) с дефолтным защитным интервалом.
func NewModem8(delta Fxp, s int) Modem8 {
\treturn newModem8(delta, s, m8GuardSamples)
}

// newModem8 — созвездие и пороги для (δ, S, skip): skip сэмплов в начале окна
// исключаются из интеграла; пороги ×(S−skip). Skip обязан совпадать на обеих
// сторонах (он часть дефолта модуляции, не конфиг).
func newModem8(delta Fxp, s, skip int) Modem8 {
\tif s < 1 {
\t\ts = 1
\t}
\tif skip < 0 {
\t\tskip = 0
\t}
\tif skip > s-1 {
\t\tskip = s - 1 // хотя бы один интегрированный сэмпл обязан остаться
\t}
\tm := Modem8{S: s, Skip: skip}
\tfor l := 0; l < 8; l++ {
\t\tm.Levels[l] = Fxp(int64(delta) * int64(2*l-7) / 7)
\t}
\teff := int64(s - skip)
\tfor j := 0; j < 7; j++ {
\t\tmid := Fxp(int64(m.Levels[j].Add(m.Levels[j+1])) >> 1)
\t\tm.thr[j] = mid.Mul(FromInt(eff))
\t}
\treturn m
}''',
'''// Демодулятор — plain-sum интегратор residual по окну (как у CSK, но в 8
// уровней по серединным порогам ×S). По замерам 2026-09-01 (m8-раунды 1-5,
// agent.md): доминирующий шум классификатора — мультипликативные экскурсии
// усиления наблюдателя от хвоста (1−c)·r; они подавляются связью c=0.95
// (дефолт режима M8, m8DefaultCoupling). Guard-интервал (skip первого сэмпла)
// и receiver-side whitening измерены и ОПРОВЕРГНУТЫ как дефолт: guard хуже на
// всех S (первый сэмпл несёт основной сигнал), whitening при c=0.85 помогает
// (0.88%→0.41% бит), но c=0.95+plain чище (≈0) и проще.
type Modem8 struct {
\tS      int    // сэмплов на символьное окно
\tLevels [8]Fxp // сдвиг драйв-сайта по индексу уровня (Грей от битов потока)
\tthr    [7]Fxp // серединные пороги классификатора, заранее ×S (для Σr окна)
}

// m8DefaultCoupling — дефолт связи наблюдателя в режиме M8 (переопределяется
// явным Config.Coupling). По замеру 2026-09-01: при c=0.95 plain-sum BER ≈ 0
// на прод-поле уже при S=3-4; при историческом 0.85 — 0.4-0.9% бит (rep3 на
// пределе). Поля сертифицированы пробой сходимости на c ∈ {0.75, 0.85, 0.95}.
var m8DefaultCoupling = MustDecimal("0.95")

// NewModem8 — созвездие и пороги для (δ, S).
func NewModem8(delta Fxp, s int) Modem8 {
\tif s < 1 {
\t\ts = 1
\t}
\tm := Modem8{S: s}
\tfor l := 0; l < 8; l++ {
\t\tm.Levels[l] = Fxp(int64(delta) * int64(2*l-7) / 7)
\t}
\tfor j := 0; j < 7; j++ {
\t\tmid := Fxp(int64(m.Levels[j].Add(m.Levels[j+1])) >> 1)
\t\tm.thr[j] = mid.Mul(FromInt(int64(s)))
\t}
\treturn m
}''')])

# ---------- session.go: откат skip в 3 местах + дефолт связи M8 ----------
patch("internal/chaossync/session.go", [
 ("rxdecode-plain",
'''\tS := uint64(e.symS)
\tsymIdx := e.rxCount / S
\t// M8: первые m8.Skip сэмплов окна — защитный интервал (межсимвольный
\t// транзиент), в интеграл residual не входят. CSK — без изменений.
\tif e.bps != 3 || (e.rxCount%S) >= uint64(e.m8.Skip) {
\t\te.symAcc = e.symAcc.Add(r)
\t}
\tif (e.rxCount % S) != S-1 {
\t\treturn
\t}''',
'''\tS := uint64(e.symS)
\tsymIdx := e.rxCount / S
\te.symAcc = e.symAcc.Add(r)
\tif (e.rxCount % S) != S-1 {
\t\treturn
\t}'''),
 ("adoptcand-plain",
'''\tfor k, rk := range c.resid {
\t\tif e.bps != 3 || (uint64(k)%S) >= uint64(e.m8.Skip) {
\t\t\te.symAcc = e.symAcc.Add(rk)
\t\t}
\t\tif (uint64(k) % S) == S-1 {''',
'''\tfor k, rk := range c.resid {
\t\te.symAcc = e.symAcc.Add(rk)
\t\tif (uint64(k) % S) == S-1 {'''),
 ("candsyncok-plain",
'''\t\tvar acc Fxp
\t\tk0 := w * S
\t\tif e.bps == 3 {
\t\t\tk0 += uint64(e.m8.Skip) // защитный интервал, как в боевом декодере
\t\t}
\t\tfor k := k0; k < (w+1)*S; k++ {
\t\t\tacc = acc.Add(c.resid[k])
\t\t}''',
'''\t\tvar acc Fxp
\t\tfor k := w * S; k < (w+1)*S; k++ {
\t\t\tacc = acc.Add(c.resid[k])
\t\t}'''),
 ("newendpoint-coupling",
'''func NewEndpoint(cfg Config, txDir string) *Endpoint {
\tcfg = cfg.withDefaults()''',
'''func NewEndpoint(cfg Config, txDir string) *Endpoint {
\t// M8: дефолт связи наблюдателя c=0.95 (по замеру 2026-09-01 — см. modem.go
\t// и agent.md). Делается ДО withDefaults и только здесь: withDefaults
\t// обязан оставаться режим-нейтральным (SelftestVector гейта Э1 использует
\t// его напрямую и живёт на историческом дефолте 0.85).
\tif cfg.Modulation == ModulationM8 && cfg.Coupling == 0 {
\t\tcfg.Coupling = m8DefaultCoupling
\t}
\tcfg = cfg.withDefaults()'''),
])

# ---------- cmd: -c пустой = дефолт режима ----------
for path in ["cmd/chaossync-server/main.go", "cmd/chaossync-client/main.go"]:
    patch(path, [
     ("flag-c", '\tcoupling := flag.String("c", "0.85", "связь Pecora-Carroll c")',
      '\tcoupling := flag.String("c", "", "связь Pecora-Carroll c (пусто = дефолт режима: 0.95 при m8, 0.85 при csk)")'),
     ("cfg-c", '''\tmod := chaossync.ModulationM8
\tswitch *modFlag {''',
      '''\tcpl := chaossync.Fxp(0) // 0 = дефолт режима (см. NewEndpoint)
\tif *coupling != "" {
\t\tcpl = chaossync.MustDecimal(*coupling)
\t}
\tmod := chaossync.ModulationM8
\tswitch *modFlag {'''),
     ("cfg-c2", "\t\tCoupling:   chaossync.MustDecimal(*coupling),",
      "\t\tCoupling:   cpl,"),
    ])
print("PATCH TASK2 FINAL DONE")
