import sys,pathlib,tarfile,json,hashlib,os,shutil
root=pathlib.Path(sys.argv[1]);backup=pathlib.Path(sys.argv[2]);changes={}
readme='''KS Windows x64 — клиент и исследовательские регрессионные тесты
Комплект от 08.09.2026. Целевая платформа: Windows 10/11 x64.

Это полный исполняемый комплект KS, а не весь CITP и не новый обход DPI. Go и Python не нужны. Выданные профиль и ключ требуются отдельно: архив не является активированной учётной записью.

СОСТАВ
ks-vpn-windows-amd64.exe — текущий TUN-клиент KS, без изменения wire-format и получения ключей.
wintun.dll — неизменённая официальная AMD64 DLL Wintun 0.14.1; лицензия включена.
chaossync-selftest-windows-amd64.exe — три детерминированных контрольных вектора.
ks-research-tests-windows-amd64.exe — выбранные регрессии и встроенные публичные поля R1.
START-KS.cmd / run-ks-vpn.ps1 — запуск по проверяемому IPv4-профилю.
SELFTEST.cmd / SELFTEST.ps1 / VERIFY.ps1 — хеши, автоматическое сравнение трёх векторов и офлайн-тесты.
client.example.json, expected-vectors.txt, SHA256SUMS — шаблон, эталоны и хеши.
docs, licenses, BUILD-VALIDATION.txt и provenance — доказательства и ограничения.

ЗАПУСК
1. Распакуйте в НОВУЮ папку. Сохраните старую папку клиента и профиль для отката.
2. Запустите SELFTEST.cmd без прав администратора. Он должен завершиться PASS и кодом 0. Выбранные тесты не подключаются к сети. Не обходите корпоративную политику скриптов и не отключайте защитное ПО.
3. Скопируйте client.example.json в client.json. Укажите PeerHost (буквальный IPv4), PeerPort, TunIP и EpochSeconds из УЖЕ ВЫДАННОГО профиля. 51830 в шаблоне — порт hub, не подтверждение ваших настроек. Старый профиль на 51820 должен сохранить свои параметры.
4. Безопасно перенесите выданный ключ в data\\ks-vpn.key. Ключей в архиве НЕТ. Новый локальный ключ не подключит существующую серверную учётную запись. Ограничьте NTFS-доступ; не публикуйте ключ и не запускайте одну идентичность одновременно на нескольких устройствах.
5. Запустите START-KS.cmd от имени администратора. FullTun=true включает существующую маршрутизацию IPv4 через TUN. Штатная остановка — Ctrl+C, не принудительное завершение.

ОГРАНИЧЕНИЯ
Серверы не переустанавливались, ключи не менялись. Экспериментальный наблюдатель и ротация IPv6 не включены. FullTun не является доказанным системным kill switch или защитой от утечек IPv6: нативный маршрут IPv6 может идти мимо IPv4-туннеля.
Сборка и Wine не заменяют проверку PowerShell, Wintun и подключения на физическом Windows. Фактические проверки перечислены в BUILD-VALIDATION.txt. Не отключайте подпись драйверов или антивирус.
R1/R2 — изолированная математическая модель, не доказательство скрытности трафика. Seal+28 — длина шифротекста, не весь IP-пакет. Обход DPI/ТСПУ не доказан.

ЦЕЛОСТНОСТЬ И ОТКАТ
SHA256 обнаруживает изменения при передаче, но не удостоверяет издателя. EXE и скрипты проекта не подписаны кодовой подписью. DLL совпадает с официальным дистрибутивом Wintun; проверка цепочки Authenticode на Windows отдельно не выполнялась.
Для отката штатно остановите клиент и вернитесь к сохранённой прежней папке и профилю. Комплект не устанавливает обновлятор, задачу планировщика или указатель CURRENT.
'''
changes['packaging/windows/README.ru.txt']=readme.encode()
n='packaging/windows/run-ks-vpn.ps1';s=(root/n).read_text();a=chr(92)*2+'.';b=chr(92)+'.';assert s.count(a)<=1;s=s.replace(a,b);changes[n]=s.encode()
n='packaging/windows/START-KS.cmd';changes[n]=(root/n).read_bytes().replace(b'-ExecutionPolicy Bypass',b'-ExecutionPolicy RemoteSigned')
changes['packaging/windows/SELFTEST.cmd']=b'@echo off\r\ncd /d "%~dp0"\r\npowershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File "%~dp0SELFTEST.ps1"\r\nset "RC=%ERRORLEVEL%"\r\npause\r\nexit /b %RC%\r\n'
changes['packaging/windows/SELFTEST.ps1']=b'''$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
& (Join-Path $PSScriptRoot 'VERIFY.ps1')
$expected = @(Get-Content -LiteralPath (Join-Path $PSScriptRoot 'expected-vectors.txt'))
$actual = @(& (Join-Path $PSScriptRoot 'chaossync-selftest-windows-amd64.exe'))
if ($LASTEXITCODE -ne 0 -or $actual.Count -ne 3 -or $expected.Count -ne 3) { throw 'Core selftest failed or vector count mismatch.' }
for ($i = 0; $i -lt 3; $i++) {
    if ([string]$actual[$i] -cne [string]$expected[$i]) { throw 'Core vector mismatch.' }
}
Write-Host 'PASS: all three core vectors match.'
& (Join-Path $PSScriptRoot 'ks-research-tests-windows-amd64.exe') -test.run '^(TestKSResearchLengthContract|TestKSResearchScheduleRegression|TestKsGoldenVector)$' -test.v -test.timeout 180s
if ($LASTEXITCODE -ne 0) { throw 'Research regression tests failed.' }
Write-Host 'PASS: selected offline selftests.'
'''
def state(p):
 if not p.exists():return None
 b=p.read_bytes();return {'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b),'mode':p.stat().st_mode&511}
after=json.loads((backup/'manifest.after.json').read_text());before=json.loads((backup/'manifest.complete.before.json').read_text())
for n,s in after.items():assert state(root/n)==s,n
rev=backup/'revision-02';rev.mkdir(mode=448)
with tarfile.open(rev/'before.tar.gz','x:gz') as t:
 for n in changes:
  if (root/n).exists():t.add(root/n,arcname=n,recursive=False)
(rev/'manifest.before.json').write_text(json.dumps({n:state(root/n) for n in changes},indent=2))
shutil.copy2(backup/'manifest.after.json',rev/'manifest.after.previous.json')
for n,b in changes.items():
 if n not in before:assert not (root/n).exists();before[n]=None
 p=root/n;temp=p.with_name(p.name+'.refine.tmp');temp.write_bytes(b);os.chmod(temp,420);os.replace(temp,p);after[n]=state(p)
(backup/'manifest.complete.before.json').write_text(json.dumps(before,indent=2))
(backup/'manifest.after.json').write_text(json.dumps(after,indent=2))
print('PACKAGING REFINED',len(changes),'files, revision backed up; regex verified; no production changes')
