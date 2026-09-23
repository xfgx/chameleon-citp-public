$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath($PSScriptRoot) + [IO.Path]::DirectorySeparatorChar
$count = 0
foreach ($line in Get-Content -LiteralPath (Join-Path $root 'SHA256SUMS')) {
    if ($line -notmatch '^([0-9a-fA-F]{64})  (.+)$') { throw 'Invalid manifest line' }
    $expected = $Matches[1]; $name = $Matches[2]
    $path = [IO.Path]::GetFullPath((Join-Path $root $name))
    if (-not $path.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid manifest path' }
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $expected) { throw "Checksum mismatch: $name" }
    $count++
}
if ($count -lt 6) { throw 'Incomplete manifest' }
Write-Host "PASS: $count checksums. Integrity is not a publisher signature."
