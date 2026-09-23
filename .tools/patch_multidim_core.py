import sys
nl = chr(10)
T = chr(9)

# ============ map.go: MaxChan + ObserverStepMulti ============
pm = 'internal/chaossync/map.go'
sm = open(pm, encoding='utf-8').read()

old_sites = '// Sites — размерность решётки (число сайтов CML).' + nl + 'const Sites = 8'
assert old_sites in sm, 'sites anchor'
sm = sm.replace(old_sites, old_sites + nl + nl +
'// MaxChan — максимум параллельных каналов многомерного кодирования' + nl +
'// (Рычаг 1: гиперхаос, несколько синхронизирующихся подпространств).' + nl +
'const MaxChan = 4', 1)

# ObserverStepMulti после ObserverStep (якорь — конец ObserverStep)
old_obs = T + 'x[p.Drive] = pred.Add(c.Mul(r))' + nl + T + 'return r' + nl + '}'
assert old_obs in sm, 'observer anchor'
multi = [
'',
'// ObserverStepMulti — многоканальный шаг наблюдателя (Рычаг 1). Свободный шаг,',
'// затем коррекция каждого из K драйв-сайтов своим скалярным сигналом. Возвращает',
'// per-channel residual\'ы r[ch] = y[ch] − F(x)[drives[ch]] ДО коррекции — из их',
'// динамики декодируется K независимых битовых потоков в одном хаос-сигнале.',
'// Чем больше связанных сайтов, тем сильнее (отрицательнее) условные показатели',
'// Ляпунова -> синхронизм только крепче. Перекрёстное влияние каналов меряется',
'// отдельно (лаборатория multidim), не полагается на ноль априори.',
'func (p *FieldParams) ObserverStepMulti(x *[Sites]Fxp, y []Fxp, c Fxp, drives []int) [MaxChan]Fxp {',
T + 'p.Step(x)',
T + 'var r [MaxChan]Fxp',
T + 'for ch := 0; ch < len(drives) && ch < MaxChan; ch++ {',
T + T + 'd := drives[ch]',
T + T + 'pred := x[d]',
T + T + 'r[ch] = y[ch].Sub(pred)',
T + T + 'x[d] = pred.Add(c.Mul(r[ch]))',
T + '}',
T + 'return r',
'}',
]
sm = sm.replace(old_obs, old_obs + nl + nl.join(multi), 1)
open(pm, 'w', encoding='utf-8').write(sm)
print('map.go: MaxChan + ObserverStepMulti')

# ============ schedule.go: DeriveDrives ============
ps = 'internal/chaossync/schedule.go'
ss = open(ps, encoding='utf-8').read()
anchor = '// fieldConverges — детерминированная проверка'
assert anchor in ss, 'fieldConverges anchor'
dd = [
'// DeriveDrives — выбор k различных драйв-сайтов для многомерного кодирования.',
'// Сайты равномерно разнесены по гамильтонову циклу связи (минимум перекрёстного',
'// влияния). Детерминировано из уже выведенной топологии поля, DRBG НЕ расходует',
'// -> одноканальный путь и золотой хэш Э1 не меняются. При k=1 возвращает',
'// [base.Drive] (тождественно доказанному одноканальному пути).',
'func DeriveDrives(base *FieldParams, k int) []int {',
T + 'if k < 1 {',
T + T + 'k = 1',
T + '}',
T + 'if k > Sites {',
T + T + 'k = Sites',
T + '}',
T + '// порядок обхода цикла связи, начиная с базового драйв-сайта',
T + 'order := make([]int, 0, Sites)',
T + 'cur := base.Drive',
T + 'for len(order) < Sites {',
T + T + 'order = append(order, cur)',
T + T + 'cur = base.Next[cur]',
T + '}',
T + '// k равномерно разнесённых по циклу позиций',
T + 'drives := make([]int, 0, k)',
T + 'for i := 0; i < k; i++ {',
T + T + 'drives = append(drives, order[(i*Sites)/k])',
T + '}',
T + 'return drives',
'}',
'',
]
ss = ss.replace(anchor, nl.join(dd) + anchor, 1)
open(ps, 'w', encoding='utf-8').write(ss)
print('schedule.go: DeriveDrives')
