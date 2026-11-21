<#
.SYNOPSIS
  Puts the tools you actually use into C:\Tools.
  Sysinternals comes straight from Microsoft (live.sysinternals.com), so it is always current and you
  don't have to redistribute it. WFP Explorer and redbaron come from this repo's Tools folder.
  If the box has no internet, copy the exes into the repo's Tools folder some other way and re-run:
  anything already in Tools\ is used instead of downloading.
#>
. "$PSScriptRoot\common.ps1"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$dst = $Config.ToolsDir
New-Item -ItemType Directory $dst -Force | Out-Null

$sysint = 'Autoruns64.exe', 'autorunsc64.exe', 'procexp64.exe', 'tcpview64.exe', 'Procmon64.exe', 'sigcheck64.exe', 'strings64.exe', 'Sysmon64.exe', 'accesschk64.exe'
foreach ($f in $sysint) {
    $local = Join-Path $PSScriptRoot "Tools\$f"
    $out = Join-Path $dst $f
    if (Test-Path $local) { Copy-Item $local $out -Force; Write-Good "$f (from repo)"; continue }
    try {
        Invoke-WebRequest "https://live.sysinternals.com/$f" -OutFile $out -UseBasicParsing -ErrorAction Stop
        Write-Good "$f (downloaded)"
    } catch { Write-Bad "$f : download failed ($($_.Exception.Message))" }
}
foreach ($f in 'WFPExplorer.exe', 'redbaron.exe', 'sysmon.xml') {
    $local = Join-Path $PSScriptRoot "Tools\$f"
    if (Test-Path $local) { Copy-Item $local $dst -Force; Write-Good "$f (from repo)" } else { Write-Warn "$f missing from repo Tools folder" }
}
Get-ChildItem $dst | Unblock-File

# Accept the Sysinternals EULA once so the GUI tools don't stop to ask.
foreach ($n in 'Autoruns', 'Process Explorer', 'TCPView', 'Process Monitor', 'Sigcheck', 'Strings', 'AccessChk', 'System Monitor') {
    New-Item "HKCU:\Software\Sysinternals\$n" -Force | New-ItemProperty -Name EulaAccepted -Value 1 -PropertyType DWord -Force | Out-Null
}

Write-Host "`nTools in $dst" -ForegroundColor Cyan
Write-Host 'Rule 2.5: never use the VirusTotal options in Autoruns / Process Explorer / sigcheck (-v, -vt).' -ForegroundColor Yellow
