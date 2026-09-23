$ErrorActionPreference = 'Stop'
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
