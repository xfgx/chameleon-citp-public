import pathlib,json,shutil,hashlib,tarfile,zipfile,datetime,subprocess
r=pathlib.Path('/root/build/ks-integration-20260908');b=r/'windows-bundle';p=r/'r2-results';src=r/'project'
assert (r/'build-completed.txt').exists() and (r/'wine-completed-v2.txt').exists()
assert json.loads((p/'verification.json').read_text())['status']=='PASS'
# Preserve the initial generated packaging before refining this new release directory.
with tarfile.open(r/'bundle-before-finalization.tar.gz','x:gz') as t:
 for x in b.rglob('*'):
  if x.is_file() and x.suffix.lower() not in ['.exe','.dll']:t.add(x,arcname=str(x.relative_to(b)),recursive=False)
shutil.copytree('/root/vpn/packaging/windows',b,dirs_exist_ok=True)
shutil.copytree('/root/vpn/packaging/windows',src/'packaging/windows',dirs_exist_ok=True)
licenses={'Go-LICENSE.txt':'/usr/local/go/LICENSE','x-crypto-LICENSE.txt':'/root/go/pkg/mod/golang.org/x/crypto@v0.55.0/LICENSE','x-net-LICENSE.txt':'/root/go/pkg/mod/golang.org/x/net@v0.58.0/LICENSE','x-sys-LICENSE.txt':'/root/go/pkg/mod/golang.org/x/sys@v0.47.0/LICENSE','Wintun-Go-binding-LICENSE.txt':'/root/go/pkg/mod/golang.zx2c4.com/wintun@v0.0.0-20230126152724-0fa3db229ce2/LICENSE'}
for n,f in licenses.items():shutil.copy2(f,b/'licenses'/n)
(b/'provenance').mkdir();shutil.copy2('/root/backups/ks-integration-20260908-01/staging/wintun-provenance.json',b/'provenance/wintun.json')
for n in ['native-regression.log','loopguard.log','code-token-check.log','pe-check.json','binary-build-info.txt','wine-tests-v2.log','wine-vectors-v2.txt','build-recovery.txt']:
 shutil.copy2(r/n,b/'provenance'/n)
validation='''KS Windows x64 — actual validation, 2026-09-08
BUILT on RU, Go1.26.3, Windows AMD64, CGO=0, trimpath, buildvcs=false, readonly cached modules, no dependency downloads.
PASS: three executables compiled; independent PE32+ AMD64 header checks for all executables and DLL; Go embedded build information captured.
PASS native selected regressions: 24016 length/roundtrip cases; schedule fixed4=0/32, alternate4=32/32; current KS golden; existing TestLoopGuardDrop.
PASS Windows binaries under Wine: all three core vectors exactly match native; selected length, schedule and golden tests pass. Second run explicitly cleans up only the isolated WINEPREFIX.
NOT TESTED: PowerShell execution or Wintun/TUN/connectivity on physical Windows, complete test suite, race detector, IPv6 leak protection, kill switch, current DPI/TSPU classification or evasion.
Project EXEs and scripts are unsigned. Wintun DLL is byte-identical to the official0.14.1 AMD64 archive; local Windows Authenticode chain verification not performed.
NO live keys, active client.json or SSH credentials included. Only existing assigned profile/key can activate the client.
Production service configuration, keys, routes, wire format and key schedule were not changed or restarted.
DEVIATIONS: initial build script finished compilation but its optional file utility was absent; independent Python PE checks replaced that inspection. Initial Wine tests passed but unit shutdown timed out on a lingering winedevice process; a second bounded run uses prefix-scoped wineserver cleanup. Original logs are preserved in the research evidence.
Integrity hashes do not establish publisher authenticity.
'''
(b/'BUILD-VALIDATION.txt').write_text(validation)
(b/'BUILD-PENDING.txt').unlink()
# Allowlisted build-source snapshot; never whole /root/vpn or bin/data.
manifest={str(x.relative_to(src)):hashlib.sha256(x.read_bytes()).hexdigest() for x in src.rglob('*') if x.is_file()}
assert not any(n.endswith('.key') or 'bin/data/' in n or 'ssh_' in n or n.endswith('client.json') for n in manifest)
(b/'provenance/source-sha256.json').write_text(json.dumps(manifest,indent=2))
with tarfile.open(b/'provenance/ks-build-source.tar.gz','x:gz') as t:
 for n in sorted(manifest):t.add(src/n,arcname=n,recursive=False)
summary=json.loads((p/'summary.json').read_text())
report='''# KS-R2 — квантование и серии пропусков

## Вывод
Устойчивость к IID-потерям не переносится автоматически на серии потерь. При 16-битном наблюдении и целевых 10% потерь допуск RMS<0.001 выдержали 64/64 поля при IID, но только 9/64 при burst8. Реальные средние потери: 10.068130493164062% и 10.053253173828125%. Это близкие, не строго одинаковые реализации.

## Модель и границы
Все вычислительные эксперименты и основной независимый анализ выполнены на RU. 32 поля R1 +32 заранее заданных новых публичных поля, без отбраковки; 4 точности x7 режимов, всего1792 строки. Native Go Step/ObserverStepMulti, чередование четырёх наблюдаемых координат, c=.95; burn2048, measure8192, tail1024. RMS по всем8 координатам конечного окна; допуск заранее выбран RMS<.001. Q0.b nearest+saturation — общий квантователь, не production modem. Целевые потери0/1/5/10%; IID и стационарная двухсостоянийная цепь со средней серией8; целая четвёрка стирается вместе. Общие SHA256-униформы дают парные условия по точности.
Сохранены идеальные общие часы, известная фаза расписания, одинаковая динамика и отсутствие задержек, перестановки, reacquisition и прочих возмущений. Одна реализация потерь на поле и условие. Это не512 независимых полей и не сетевой тест.

## Почему 48 бит дают слишком оптимистичный контроль
При точном совпадении целых состояний одинаковый Step сохраняет равенство даже при пропуске коррекции. Точное наблюдение не вносит нового возмущения. Это инвариант идентичной детерминированной модели, а не доказательство устойчивости реального канала. Все64 поля дали точную нулевую конечную ошибку в каждом48-битном условии. При12/16/24 бит точного конечного равенства нет даже без потерь, хотя допуск без потерь выполнен на64/64 полях.

## Основная таблица: допуск и разброс
p95 — линейный выборочный квантиль по64 полям; max — худшая полевая RMS, не гарантия за пределами этого окна.

|Бит|Целевая потеря %|Режим|RMS<.001|Медиана RMS|p95 RMS|max RMS|Реальная потеря %|
|---|---|---|---|---|---|---|---|
'''
for x in summary:
 if x['cohort']=='all':report+=f"|{x['bits']}|{x['loss_target']}|{x['pattern']}|{x['tolerance_success']}/{x['n']}|{x['rms_median']:.9g}|{x['rms_p95']:.9g}|{x['rms_max']:.9g}|{x['loss_realized_percent']:.6f}|\n"
report+='''
## Проверки и важные отрицательные результаты
40004 проверки квантователя;1792 уникальные строки без пропусков;1536 независимых сверок количества стираний;32 исходных набора параметров и начальных состояний совпали с R1;28 pooled-групп пересчитаны другим способом. Полные cohort-агрегаты, пары и длины серий — в JSON/CSV.
При16 бит и10% burst RMS хуже IID на всех64 парных полях. При1% это лишь39/64: утверждение «burst всегда хуже» неверно. Малая медиана не исключает тяжёлый хвост: при24 бит и10% burst медиана ниже порога, но31/64 полей порог не выдержали. Допуск RMS также не ограничивает каждый отдельный выброс: при16 бит,10% IID максимальная абсолютная ошибка достигает0.02200593, несмотря на64/64 успехов по RMS.

## Следующие опровержимые вопросы, пока не проверены
1. Отделить влияние порядка потерь от их количества: многократные перестановки каждой той же маски, с неизменным числом стираний. Оценивать парный эффект и доверительные интервалы по полям, а не по зависимым условиям.
2. Проверить нарушение идеальных общих часов, фазовый сдвиг на1 тик и восстановление после него в офлайн-стенде; это может разрушить оптимистичный48-битный контроль.
3. Проверить robust endpoint: вероятность превышения максимальной ошибки и время восстановления, а не только среднюю RMS.
Ни один пункт не внедрён в транспорт. Не предполагается воздействие на чужие устройства или воспроизведение уязвимостей.

## Prior art и статус новизны
Квантованная синхронизация и ограничения канала изучались задолго до этой работы. Ближайшие линии:
- Fradkov, Andrievsky, Evans: Controlled Synchronization ... under Information Constraints,2007/2008. https://arxiv.org/abs/0712.0636 — прочитана аннотация; Lurie/Chua, бинарный меняющийся кодер. Не теорема для нашего Q16.48 кольца.
- Hasslinger, Hohlfeld: The Gilbert-Elliott Model for Packet Loss in Real Time Services on the Internet. https://people.computing.clemson.edu/~jmarty/projects/lowLatencyNetworking/papers/APPFEC/GEModelForLossinTheRTInternet.pdf — изучены определения двухсостоянийной модели и стационарных вероятностей; burst8 — стандартная модель, не новый механизм.
- Xu, Mo, Xie: Distributed Consensus over Markovian Packet Loss Channels. https://ar5iv.labs.arxiv.org/html/1810.03314 — введение и модель показывают, почему IID не покрывает временную корреляцию; линейный multi-agent consensus, не наша нелинейная модель.
Точной копии этой реализации и матрицы условий в просмотренных источниках не найдено. Это ограниченное новое количественное свидетельство для проекта, а не доказанный мировой приоритет, фундаментальное открытие или найденный обход DPI/ТСПУ.

## Воспроизведение
Из корня снимка проекта: go build -o channel-lab ./research/ks-r2-20260908/channel_lab
Затем: ./channel-lab -fields internal/chaossync/testdata/ks_r1_fields.json -out NEW_EMPTY_PATH
Агрегация: analyze_r2.v2.py использует абсолютный путь исходного RU-каталога; при переносе явно измените переменную r в копии скрипта. Нужны Go1.26.3 и кэш зависимостей; анализ — Python3 +NumPy.

## Отклонения исполнения
R2 завершён за15.697076877s по run.json под CPU25%, память512MiB, private network. Первый анализ остановился до агрегатов на метаданных cycle: Go-экспорт не сохраняет эту фиксированную топологию отдельным полем. V2 отдельно проверяет, что все исходные cycle равны[0..7], и сравнивает все сохранённые параметры; исходные результаты не менялись и не перезапускались. Первая неудача и оба скрипта сохранены. Компиляция началась с CPU25%, затем только сборочная квота повышена до50%; квота эксперимента не менялась. Локальная обработка — копирование, QA и визуализация, не повтор эксперимента.
'''
(r/'R2-REPORT.md').write_text(report);shutil.copy2(r/'R2-REPORT.md',b/'docs/R2-REPORT.md');shutil.copy2(p/'summary.csv',b/'docs/R2-summary.csv')
# Separate complete research evidence, including unsuccessful setup/analysis logs.
e=r/'research-deliverable';e.mkdir();shutil.copytree(p,e/'results');shutil.copytree(src/'research/ks-r2-20260908',e/'lab')
for n in ['R2-REPORT.md','analyze_r2.py','analyze_r2.v2.py','r2.log','r2-analysis.log','r2-analysis-v2.log','run_r2.sh','run_build.sh','run_wine.sh','run_wine_v2.sh','build.log','build-recovery.txt','native-regression.log','loopguard.log','code-token-check.log','pe-check.json','expected-vectors.txt','wine.log','wine-tests.log','wine-init.log','wine-v2.log','wine-tests-v2.log','wine-vectors-v2.txt','binary-build-info.txt']:
 if (r/n).is_file():shutil.copy2(r/n,e/n)
shutil.copy2(src/'internal/chaossync/ks_research_regression_test.go',e/'ks_research_regression_test.go')
shutil.copy2('/root/backups/ks-integration-20260908-01/restore-test.PASS.txt',e/'restore-test.PASS.txt')
def sums(folder):
 lines=[]
 for x in sorted(folder.rglob('*')):
  if x.is_file() and x.name!='SHA256SUMS':lines.append(hashlib.sha256(x.read_bytes()).hexdigest()+'  '+str(x.relative_to(folder)))
 (folder/'SHA256SUMS').write_text('\n'.join(lines)+'\n');return len(lines)
print('MANIFESTS',sums(b),sums(e))
for folder,name in [(b,'ks-windows-client-20260908-research.zip'),(e,'KS-R2-RU-2026-09-08.zip')]:
 z=r/name
 with zipfile.ZipFile(z,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as f:
  for x in sorted(folder.rglob('*')):
   if x.is_file():f.write(x,arcname=str(pathlib.Path(folder.name)/x.relative_to(folder)))
 with zipfile.ZipFile(z) as f:assert f.testzip() is None
 print('ARCHIVE',str(z),z.stat().st_size,hashlib.sha256(z.read_bytes()).hexdigest())
