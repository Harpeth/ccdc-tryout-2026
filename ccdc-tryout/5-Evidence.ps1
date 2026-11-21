<#
.SYNOPSIS
  Collect evidence on one suspicious file or process and write a pre-filled IR report.
  Read-only unless you add -Quarantine (after 12:00 only).
.DESCRIPTION
  For the file (or the process's file) it records:
    - SHA256, size, signer, version info (a FileDescription that doesn't match the name = disguised binary)
    - timestamps (don't trust them: red team timestomps)
    - URLs, IPs, webhooks and DLL names found in its strings
    - every place that starts it: scheduled tasks, Run keys, services, Startup folders, WMI, IFEO, LSA keys
    - running copies, their command lines, parents, and network connections
    - (-FindCopies) other files on C:\ with the same hash: the "spray" problem from the debrief
  Writes C:\Backups\IR\<time>-<name>.md : open it, fill the blanks, paste into the IR form.
.EXAMPLE
  .\5-Evidence.ps1 -Path C:\Windows\System32\AppLocker\svchost.exe
  .\5-Evidence.ps1 -ProcessId 4412
  .\5-Evidence.ps1 -Path C:\Users\Public\x.exe -FindCopies
  .\5-Evidence.ps1 -Path C:\Users\Public\x.exe -Quarantine     # after noon: kill it, copy to quarantine, delete it
#>
param(
    [string]$Path,
    [int]$ProcessId,
    [switch]$FindCopies,
    [switch]$Quarantine,
    [switch]$Force
)
. "$PSScriptRoot\common.ps1"

if ($ProcessId) {
    $wp = Get-WmiObject Win32_Process -Filter "ProcessId=$ProcessId"
    if (-not $wp) { Write-Bad "No process $ProcessId"; exit 1 }
    $Path = $wp.ExecutablePath
    if (-not $Path) { Write-Bad "Can't read the path of PID $ProcessId (protected process?)"; exit 1 }
}
if (-not $Path -or -not (Test-Path $Path)) { Write-Bad "Give -Path to an existing file, or -ProcessId"; exit 1 }
$file = Get-Item $Path -Force
$name = $file.Name
$full = $file.FullName
$esc = [regex]::Escape($name)

# ---------------------------------------------------------------- identity
Write-Step "Evidence: $full"
$sha = (Get-FileHash $full -Algorithm SHA256).Hash
$sig = Get-AuthenticodeSignature $full -ErrorAction SilentlyContinue
$ver = $file.VersionInfo
$signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '(none)' }
Write-Good "SHA256 $sha"
Write-Good "Signature: $($sig.Status) - $signer"
$disguise = ''
if ($ver.OriginalFilename -and ($ver.OriginalFilename -replace '\.mui$') -ne $name) { $disguise = "OriginalFilename is '$($ver.OriginalFilename)' but the file is named '$name'" }
if ($disguise) { Write-Warn $disguise }

# ---------------------------------------------------------------- strings
Write-Step 'Strings (URLs, IPs, webhooks, DLLs)'
$iocs = @()
if ($file.Length -lt 60MB) {
    $bytes = [IO.File]::ReadAllBytes($full)
    $text = [Text.Encoding]::ASCII.GetString($bytes) + "`n" + [Text.Encoding]::Unicode.GetString($bytes)
    $pat = 'https?://[\w\.\-:/%\?=&#~]{4,200}|\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b|discord(?:app)?\.com/api/webhooks/[\w/\-]+|[\w\-]{3,40}\.dll\b|\\\\[\w\.\-]+\\[\w\$]+|[A-Za-z]:\\[\w\\\.\- ]{4,120}\.(?:exe|dll|ps1|bat|vbs)'
    $iocs = [regex]::Matches($text, $pat) | ForEach-Object { $_.Value } |
        Where-Object { $_ -notmatch '^(0\.|255\.|1\.0\.0|2\.0\.0)' -and $_ -notmatch '^(kernel32|ntdll|user32|advapi32|msvcrt|ws2_32|ole32|oleaut32|shell32|gdi32|comctl32|crypt32|rpcrt4|shlwapi|bcrypt|secur32|version|winhttp|wininet|iphlpapi|dbghelp|ucrtbase|vcruntime\d*|api-ms-win[\w\-]*)\.dll$' } |
        Select-Object -Unique -First 40
    foreach ($i in $iocs) { Write-Host "    $i" }
    if (-not $iocs) { Write-Good 'Nothing obvious (packed or Go binary? try: strings64 -n 8 <file> | findstr /i "http dll webhook")' }
} else { Write-Warn 'File > 60 MB, skipped. Use strings64.' }

# ---------------------------------------------------------------- what starts it
Write-Step 'What starts it'
$starts = @()
Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
    $t = $_
    foreach ($a in @($t.Actions)) {
        if ("$($a.Execute) $($a.Arguments)" -match $esc) {
            $trig = (@($t.Triggers) | ForEach-Object { $_.CimClass.CimClassName -replace 'MSFT_Task|Trigger' }) -join ','
            $starts += "Scheduled task ``$($t.TaskPath)$($t.TaskName)`` (trigger: $trig, author: $($t.Author)) runs ``$($a.Execute) $($a.Arguments)``"
        }
    }
}
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
$keys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
          'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon')
Get-ChildItem HKU:\ -ErrorAction SilentlyContinue | ForEach-Object { $keys += "HKU:\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Run" }
foreach ($k in $keys) {
    $p = Get-ItemProperty $k -ErrorAction SilentlyContinue
    if (-not $p) { continue }
    $p.PSObject.Properties | Where-Object { "$($_.Value)" -match $esc -and $_.Name -notmatch '^PS' } |
        ForEach-Object { $starts += "Registry ``$k`` value ``$($_.Name)`` = ``$($_.Value)``" }
}
Get-WmiObject Win32_Service | Where-Object { $_.PathName -match $esc } |
    ForEach-Object { $starts += "Service ``$($_.Name)`` ($($_.StartMode), runs as $($_.StartName)): ``$($_.PathName)``" }
$sd = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup") + (Get-ChildItem C:\Users -Directory -ErrorAction SilentlyContinue | ForEach-Object { "$($_.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" })
foreach ($d in $sd) { if ($full -like "$d\*") { $starts += "Startup folder ``$d``" } }
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue | Where-Object { $_.CommandLineTemplate -match $esc } |
    ForEach-Object { $starts += "WMI consumer ``$($_.Name)``: ``$($_.CommandLineTemplate)``" }
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue | ForEach-Object {
    $dbg = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Debugger
    if ($dbg -match $esc) { $starts += "IFEO debugger on ``$($_.PSChildName)``: ``$dbg``" }
}
$base = [IO.Path]::GetFileNameWithoutExtension($name)
$lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
foreach ($n in 'Notification Packages', 'Security Packages', 'Authentication Packages') {
    if (@($lsa.$n) -contains $base) { $starts += "LSA ``$n`` contains ``$base`` (loaded into lsass)" }
}
$sp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders' -ErrorAction SilentlyContinue).SecurityProviders
if ($sp -match $esc) { $starts += "``SecurityProviders`` contains ``$name`` (loaded into lsass)" }
if (Get-Process lsass -Module -ErrorAction SilentlyContinue | Where-Object { $_.FileName -eq $full }) { $starts += 'Currently LOADED INSIDE lsass.exe' }
if ($starts) { $starts | ForEach-Object { Write-Warn $_ } } else { Write-Good 'No autostart found by name (check Autoruns: it may start from another binary)' }

# ---------------------------------------------------------------- running + network
Write-Step 'Running copies and connections'
$procs = @(Get-WmiObject Win32_Process | Where-Object { $_.ExecutablePath -eq $full })
$run = @()
foreach ($pr in $procs) {
    $parent = Get-WmiObject Win32_Process -Filter "ProcessId=$($pr.ParentProcessId)" -ErrorAction SilentlyContinue
    $owner = $pr.GetOwner(); $who = if ($owner.User) { "$($owner.Domain)\$($owner.User)" } else { '?' }
    $conns = Get-NetTCPConnection -OwningProcess $pr.ProcessId -ErrorAction SilentlyContinue |
        Where-Object { $_.RemoteAddress -notmatch '^(0\.0\.0\.0|::|127\.|::1)$' } |
        ForEach-Object { "$($_.RemoteAddress):$($_.RemotePort) ($($_.State))" }
    $line = "PID $($pr.ProcessId) as $who, parent $($parent.Name) (PID $($pr.ParentProcessId)), cmd: ``$($pr.CommandLine)``"
    if ($conns) { $line += "; connections: $($conns -join ', ')" }
    $run += $line
    Write-Warn $line
}
if (-not $procs) { Write-Good 'Not running right now' }

# ---------------------------------------------------------------- copies
$copies = @()
if ($FindCopies) {
    Write-Step 'Other copies on C:\ (same size, then same hash) - takes a minute'
    Get-ChildItem C:\ -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Length -eq $file.Length -and $_.FullName -ne $full } |
        ForEach-Object { if ((Get-FileHash $_.FullName -ErrorAction SilentlyContinue).Hash -eq $sha) { $copies += $_.FullName; Write-Warn "COPY: $($_.FullName)" } }
    if (-not $copies) { Write-Good 'No other copies' }
}

# ---------------------------------------------------------------- MITRE guess
$mitre = @()
$all = $starts -join ' '
if ($all -match 'Scheduled task')       { $mitre += 'T1053.005 Scheduled Task' }
if ($all -match 'Registry .*Run')       { $mitre += 'T1547.001 Registry Run Keys / Startup Folder' }
if ($all -match 'Startup folder')       { $mitre += 'T1547.001 Registry Run Keys / Startup Folder' }
if ($all -match 'Service ')             { $mitre += 'T1543.003 Windows Service' }
if ($all -match 'WMI')                  { $mitre += 'T1546.003 WMI Event Subscription' }
if ($all -match 'IFEO')                 { $mitre += 'T1546.012 IFEO Injection / T1546.008 Accessibility Features' }
if ($all -match 'Notification Packages'){ $mitre += 'T1556.002 Password Filter DLL' }
if ($all -match 'Security Packages|SecurityProviders') { $mitre += 'T1547.005 Security Support Provider' }
if ($all -match 'INSIDE lsass')         { $mitre += 'T1055 Process Injection' }
if ($iocs -match 'discord')             { $mitre += 'T1567 Exfiltration Over Web Service' }
if ($run -match 'connections')          { $mitre += 'T1071.001 Web Protocols (C2)' }
if ($disguise -or $name -match '^(svchost|lsass|csrss|services|smss|winlogon|explorer)\.exe$' -and $full -notmatch '^C:\\Windows\\(System32|explorer)') { $mitre += 'T1036.005 Masquerading' }
$mitre = $mitre | Select-Object -Unique

# ---------------------------------------------------------------- report
$irDir = Join-Path $Config.BackupDir 'IR'
New-Item -ItemType Directory $irDir -Force | Out-Null
$rep = Join-Path $irDir "$(Get-Date -Format 'HHmm')-$name.md"
$bl = { param($a) if ($a) { ($a | ForEach-Object { "- $_" }) -join "`n" } else { '- none found' } }
@"
# IR: $name on $env:COMPUTERNAME

**Title:** ______________________________
**Host:** $env:COMPUTERNAME ($((Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notmatch '^127\.|^169\.254' } | Select-Object -First 1).IPAddress)), $((Get-WmiObject Win32_OperatingSystem).Caption)
**Affected scored service:** ______
**Found:** $(Get-Date -Format 'yyyy-MM-dd HH:mm') with ______ (tool / tab)

## What it is
- Path: ``$full``
- SHA256: ``$sha``
- Size: $($file.Length) bytes
- Signature: $($sig.Status) - $signer
- Version info: Description '$($ver.FileDescription)', Company '$($ver.CompanyName)', OriginalFilename '$($ver.OriginalFilename)'
- Timestamps (may be faked): created $($file.CreationTime), modified $($file.LastWriteTime)
$(if ($disguise) { "- Disguise: $disguise" })

## How it starts
$(& $bl $starts)

## Running / network
$(& $bl $run)

## Indicators from strings
$(& $bl ($iocs | ForEach-Object { "``$_``" }))
$(if ($FindCopies) { "`n## Other copies (same SHA256)`n" + (& $bl $copies) })

## MITRE ATT&CK
$(& $bl $mitre)

## Impact
______ (credentials? SYSTEM shell? persistence? C2?)

## Actions taken
- [ ] Removed persistence: ______ (Autoruns -> Delete)
- [ ] Killed PID(s): ______
- [ ] Deleted / quarantined file(s): ______
- [ ] Blocked C2 IP: ______
- [ ] Confirmed gone: Autoruns refreshed, TCPView quiet, not back after ______ min

## Recommendation
______

## Evidence
Screenshots: Autoruns entry, this script's output, TCPView.
"@ | Out-File $rep -Encoding UTF8
Write-Host "`nIR draft -> $rep   (notepad `"$rep`")" -ForegroundColor Cyan

# ---------------------------------------------------------------- quarantine (after noon)
if ($Quarantine) {
    if ((Get-Date).Hour -lt 12 -and -not $Force) { Write-Bad 'Before 12:00 - removal is not allowed. Not quarantining. (-Force if the clock is wrong)'; exit 1 }
    foreach ($w in $Config.WhitelistProcesses) { if ($w -and $name -like $w) { Write-Bad "$name is whitelisted - not touching it"; exit 1 } }
    Write-Step 'Quarantine'
    foreach ($pr in $procs) { Stop-Process -Id $pr.ProcessId -Force -ErrorAction SilentlyContinue; Write-Good "Killed PID $($pr.ProcessId)" }
    $q = Join-Path $Config.BackupDir 'quarantine'
    New-Item -ItemType Directory $q -Force | Out-Null
    icacls $q /inheritance:r /grant:r 'BUILTIN\Administrators:(OI)(CI)F' 'NT AUTHORITY\SYSTEM:(OI)(CI)F' | Out-Null
    foreach ($f in @($full) + $copies) {
        $h = (Get-FileHash $f).Hash.Substring(0, 12)
        Copy-Item $f (Join-Path $q "$([IO.Path]::GetFileName($f)).$h.quarantine") -Force -ErrorAction SilentlyContinue
        try { Remove-Item $f -Force -ErrorAction Stop; Write-Good "Deleted $f" }
        catch {
            takeown /f "$f" | Out-Null; icacls "$f" /grant Administrators:F | Out-Null
            try { Remove-Item $f -Force -ErrorAction Stop; Write-Good "Deleted $f (after takeown)" }
            catch { Write-Bad "Could not delete $f (in use / loaded in lsass?). Remove its autostart, reboot, delete again." }
        }
    }
    Write-Warn 'The file is gone, but its AUTOSTART is not: delete those entries in Autoruns, then re-run this to confirm.'
}
