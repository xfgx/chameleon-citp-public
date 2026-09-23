$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
& (Join-Path $PSScriptRoot 'VERIFY.ps1')
$cfgPath = Join-Path $PSScriptRoot 'client.json'
if (-not (Test-Path -LiteralPath $cfgPath -PathType Leaf)) { throw 'Copy client.example.json to client.json and fill your assigned profile first.' }
$cfg = Get-Content -Raw -LiteralPath $cfgPath | ConvertFrom-Json
$peer = $null
if (-not [Net.IPAddress]::TryParse([string]$cfg.PeerHost,[ref]$peer) -or $peer.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { throw 'PeerHost must be the assigned literal IPv4 node address.' }
if ([string]$cfg.TunIP -notmatch '^([0-9]{1,3}\.){3}[0-9]{1,3}/(2[0-9]|3[0-2]|1[0-9]|[0-9])$') { throw 'TunIP must be the assigned IPv4 CIDR.' }
$tun = $null
if (-not [Net.IPAddress]::TryParse(([string]$cfg.TunIP).Split('/')[0],[ref]$tun)) { throw 'Invalid TunIP address.' }
foreach ($port in @($cfg.PeerPort,$cfg.ListenPort)) { if ([int]$port -lt 1 -or [int]$port -gt 65535) { throw 'Invalid UDP port.' } }
if ([int]$cfg.EpochSeconds -lt 1) { throw 'EpochSeconds must match the server and be positive.' }
if ($cfg.FullTun -isnot [bool]) { throw 'FullTun must be a JSON boolean.' }
$keyPath = Join-Path $PSScriptRoot 'data\ks-vpn.key'
if (-not (Test-Path -LiteralPath $keyPath -PathType Leaf)) { throw 'Missing assigned key: data\ks-vpn.key. Do not generate a replacement for an existing server profile.' }
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run START-KS.cmd as administrator.' }
$clientArgs = @('-tunip',[string]$cfg.TunIP,'-peerhost',[string]$cfg.PeerHost,'-peerport',[string]$cfg.PeerPort,'-listen',[string]$cfg.ListenPort,'-keyfile',$keyPath,'-T',[string]$cfg.EpochSeconds)
if ($cfg.FullTun) { $clientArgs += '-fulltun' }
Write-Host 'IPv4 transport only. No experimental observer or automatic IPv6 rotation. Stop with Ctrl+C.'
& (Join-Path $PSScriptRoot 'ks-vpn-windows-amd64.exe') @clientArgs
exit $LASTEXITCODE
