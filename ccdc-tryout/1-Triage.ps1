<#
.SYNOPSIS
  Read-only triage. Safe before noon: it backs things up and REPORTS, it never removes anything.
.DESCRIPTION
  Writes everything to C:\Backups\triage-<time>\ :
    FINDINGS.txt   - the hit list to work through after 12:00
    persist.json   - snapshot of autostart locations, for -Compare later
    *.csv / *.txt  - raw inventory, plus backups (services.reg, firewall.wfw, DNS zones, GPOs)
.EXAMPLE
  .\1-Triage.ps1                                  # morning run, makes the baseline
  .\1-Triage.ps1 -Compare C:\Backups\triage-20261121-091500\persist.json   # what is NEW since then
  .\1-Triage.ps1 -NoBackup                        # rerun quickly without redoing backups
#>
param(
    [string]$Compare,          # path to a persist.json, or the word: latest
    [switch]$NoBackup
)
. "$PSScriptRoot\common.ps1"

if ($Compare -eq 'latest') {
    $Compare = Get-ChildItem $Config.BackupDir -Directory -Filter 'triage-*' -ErrorAction SilentlyContinue | Sort-Object Name |
        ForEach-Object { Join-Path $_.FullName 'persist.json' } | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $Compare) { Write-Host '[X] No finished triage with a persist.json yet. Run .\1-Triage.ps1 once without -Compare and let it finish.' -ForegroundColor Red; exit 1 }
    Write-Host "Comparing against the FIRST (morning) baseline: $Compare" -ForegroundColor Cyan
}
$Run = New-RunDir 'triage'
$Findings = New-Object System.Collections.ArrayList
$Persist  = New-Object System.Collections.ArrayList
$IsDC = Test-IsDC

function Add-Finding([string]$Area, [string]$Text) {
    $tag = ''
    foreach ($w in $Config.WhitelistProcesses) { if ($w -and $Text -like "*$w*") { $tag = ' [WHITELISTED - leave it]' } }
    foreach ($w in $Config.WhitelistIPs)       { if ($w -and $Text -like "*$w*") { $tag = ' [WHITELISTED - leave it]' } }
    [void]$Findings.Add("[$Area] $Text$tag")
    "[$Area] $Text$tag" | Out-File "$Run\FINDINGS.txt" -Append
    Write-Warn "[$Area] $Text$tag"
}

# A genuine Microsoft binary: valid signature from Microsoft AND its internal name matches the file name.
# A copied Windows binary (ping.exe renamed to svchost.exe) fails this: it loses its catalog signature,
# or its OriginalFilename gives it away. Genuine ones in odd paths (OneDrive, Defender) are not flagged.
$TrustCache = @{}
function Test-TrustedMs([string]$exe) {
    if (-not $exe -or -not (Test-Path $exe -ErrorAction SilentlyContinue)) { return $false }
    if ($TrustCache.ContainsKey($exe)) { return $TrustCache[$exe] }
    $ok = $false
    try {
        $sig = Get-AuthenticodeSignature $exe -ErrorAction Stop
        if ($sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -match 'O=Microsoft Corporation') {
            $orig = ((Get-Item $exe).VersionInfo.OriginalFilename -replace '\.mui$', '')
            $ok = (-not $orig) -or ($orig -ieq [IO.Path]::GetFileName($exe))
        }
    } catch {}
    $TrustCache[$exe] = $ok
    return $ok
}
function Add-Persist([string]$Area, [string]$Id) { [void]$Persist.Add("$Area|$Id") }

# Paths real software rarely runs from. Used to flag tasks, services, Run keys and processes.
$BadPath = '\\Users\\Public\\|\\AppData\\|\\ProgramData\\(?!Microsoft\\Windows Defender)|\\Temp\\|\\Windows\\Tasks\\|\\System32\\(Com|AppLocker|Tasks|spool\\drivers\\color)\\|\\PerfLogs\\|\\Recycle'
$BadArgs = '-enc|-e |frombase64|iex|invoke-expression|downloadstring|downloadfile|http:|https:|mshta|regsvr32|rundll32|certutil|bitsadmin|wscript|cscript|-w hidden|-windowstyle h'

Write-Host "Triage of $env:COMPUTERNAME  ->  $Run" -ForegroundColor Cyan
$role = Get-HostRole
if ($role) { Write-Good "Role guess: $role ($($Roles[$role].Desc))" } else { Write-Warn 'Hostname did not match a role in common.ps1' }

# ---------------------------------------------------------------- backups
if (-not $NoBackup) {
    Write-Step 'Backups'
    reg export 'HKLM\SYSTEM\CurrentControlSet\Services' "$Run\services.reg" /y | Out-Null
    Write-Good 'services.reg (use afternoon\Restore-Service.ps1 -sourceFile <this> -targetService <name>)'
    netsh advfirewall export "$Run\firewall.wfw" | Out-Null
    Write-Good 'firewall.wfw (restore: netsh advfirewall import <file>)'
    if (Get-Service DNS -ErrorAction SilentlyContinue) {
        $dnsOut = Join-Path $Run 'dns'
        New-Item -ItemType Directory $dnsOut -Force | Out-Null
        Get-DnsServerZone -ErrorAction SilentlyContinue | Where-Object { -not $_.IsAutoCreated -and $_.ZoneName -ne 'TrustAnchors' } | ForEach-Object {
            $f = "triage-$($_.ZoneName).dns"
            Export-DnsServerZone -Name $_.ZoneName -FileName $f -ErrorAction SilentlyContinue
            Move-Item "$env:SystemRoot\System32\dns\$f" $dnsOut -Force -ErrorAction SilentlyContinue
        }
        Write-Good "DNS zones -> $dnsOut"
    }
    if ($IsDC) {
        Import-Module ActiveDirectory, GroupPolicy -ErrorAction SilentlyContinue
        $gpo = Join-Path $Run 'gpo'; New-Item -ItemType Directory $gpo -Force | Out-Null
        Backup-GPO -All -Path $gpo -ErrorAction SilentlyContinue | Out-Null
        Write-Good "GPOs -> $gpo"
        Get-ADUser -Filter * -Properties Enabled, MemberOf, PasswordLastSet, LastLogonDate, AdminCount |
            Select-Object SamAccountName, Enabled, AdminCount, PasswordLastSet, LastLogonDate, @{n='Groups';e={($_.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' }) -join ';'}} |
            Export-Csv "$Run\ad-users.csv" -NoTypeInformation
        Write-Good 'ad-users.csv'
    }
}

# ---------------------------------------------------------------- system + accounts
Write-Step 'System and accounts'
Get-WmiObject Win32_OperatingSystem | Select-Object CSName, Caption, Version, LastBootUpTime | Format-List | Out-File "$Run\os.txt"
Get-LocalUser -ErrorAction SilentlyContinue | Select-Object Name, Enabled, LastLogon, PasswordLastSet | Export-Csv "$Run\local-users.csv" -NoTypeInformation
$admins = net localgroup Administrators 2>$null | Select-Object -Skip 6 | Where-Object { $_ -and $_ -notmatch 'command completed' }
$admins | Out-File "$Run\local-admins.txt"
foreach ($a in $admins) { Add-Persist 'LocalAdmin' "$a" }
$sess = quser 2>$null
if ($sess) { $sess | Out-File "$Run\sessions.txt"; Write-Good "Logged-on sessions (log off old Domain Admin sessions - token theft): $(@($sess).Count - 1)" }
Write-Good "Local Administrators: $($admins -join ', ')"
foreach ($u in $Config.ProtectedUsers) {
    $isAdm = $admins | Where-Object { $_ -match "(^|\\)$u$" }
    if (-not $isAdm -and -not $IsDC) { Write-Warn "$u is not in local Administrators here (may be granted through a domain group - check, do NOT change it)" }
}

if ($IsDC) {
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    foreach ($g in 'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'DnsAdmins', 'Account Operators', 'Server Operators', 'Backup Operators', 'Print Operators', 'Group Policy Creator Owners') {
        $m = @(Get-ADGroupMember $g -Recursive -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SamAccountName)
        "$g : $($m -join ', ')" | Out-File "$Run\ad-privileged.txt" -Append
        foreach ($x in $m) { Add-Persist 'Group' "$g=$x" }
        if (($g -in @('DnsAdmins', 'Account Operators', 'Server Operators', 'Backup Operators', 'Print Operators', 'Schema Admins')) -and ($m.Count -gt 0)) {
            Add-Finding 'AD' "$g has members: $($m -join ', ')"
        }
    }
    Write-Good 'Privileged groups -> ad-privileged.txt (review Domain Admins by hand)'
    Get-ADUser -Filter * | ForEach-Object { Add-Persist 'ADUser' $_.SamAccountName }
    Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' | ForEach-Object { Add-Finding 'AD' "AS-REP roastable (no preauth): $($_.SamAccountName)" }
    Get-ADUser -Filter 'ServicePrincipalName -like "*"' -Properties ServicePrincipalName | Where-Object { $_.SamAccountName -ne 'krbtgt' } |
        ForEach-Object { Add-Finding 'AD' "User with SPN (kerberoastable): $($_.SamAccountName) -> $($_.ServicePrincipalName -join ';')" }
    Get-ADUser -Filter 'PasswordNotRequired -eq $true' | ForEach-Object { Add-Finding 'AD' "PasswordNotRequired: $($_.SamAccountName)" }
    Get-ADUser -Filter 'AllowReversiblePasswordEncryption -eq $true' | ForEach-Object { Add-Finding 'AD' "Reversible encryption: $($_.SamAccountName)" }
    Get-ADComputer -Filter 'TrustedForDelegation -eq $true' | Where-Object { $_.DistinguishedName -notmatch 'OU=Domain Controllers' } |
        ForEach-Object { Add-Finding 'AD' "Unconstrained delegation (computer): $($_.Name)" }
    Get-ADUser -Filter 'TrustedForDelegation -eq $true' | ForEach-Object { Add-Finding 'AD' "Unconstrained delegation (user): $($_.SamAccountName)" }

    # DCSync: who holds replication rights on the domain root.
    $repl = @{ '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'GetChanges'; '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'GetChangesAll'; '89e95b76-444d-4c62-991a-0facbeda640c' = 'GetChangesInFilteredSet' }
    $okRepl = 'Domain Controllers|Enterprise Domain Controllers|Enterprise Read-only Domain Controllers|BUILTIN\\Administrators|Domain Admins|Enterprise Admins|NT AUTHORITY\\SYSTEM'
    try {
        $dn = (Get-ADDomain).DistinguishedName
        $acl = (Get-ADObject -Identity $dn -Properties nTSecurityDescriptor).nTSecurityDescriptor.Access
        $acl | Where-Object { $repl.ContainsKey("$($_.ObjectType)") -or "$($_.ActiveDirectoryRights)" -match 'GenericAll' } | ForEach-Object {
            $right = $repl["$($_.ObjectType)"]; if (-not $right) { $right = "$($_.ActiveDirectoryRights)" }
            if ("$($_.IdentityReference)" -notmatch $okRepl) { Add-Finding 'AD' "DCSync-capable ACE on domain root: $($_.IdentityReference) has $right" }
        }
    } catch { Write-Warn "Could not read domain ACL: $_" }
}

# ---------------------------------------------------------------- LSA
Write-Step 'LSA plug-ins (password filters, SSPs) - check BEFORE rotating passwords'
$lsaHits = Get-LsaFindings
foreach ($h in $lsaHits) { Add-Finding 'LSA' "$($h.Key) contains unknown entry '$($h.Value)'"; Add-Persist 'LSA' "$($h.Key)=$($h.Value)" }
if (-not $lsaHits) { Write-Good 'No unknown LSA packages' }
$ppl = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue).RunAsPPL
if ($ppl -ne 1) { Write-Warn 'RunAsPPL is off (LSASS is not protected - see 3-Harden.ps1 -RunAsPPL)' }
Get-Process lsass -Module -ErrorAction SilentlyContinue | Where-Object { $_.FileName -notmatch '\\Windows\\(System32|WinSxS)\\' } |
    ForEach-Object { Add-Finding 'LSA' "DLL loaded in lsass from odd path: $($_.FileName)" }
Get-Process lsass -Module -ErrorAction SilentlyContinue | ForEach-Object {
    $s = Get-AuthenticodeSignature $_.FileName -ErrorAction SilentlyContinue
    if ($s -and $s.Status -ne 'Valid') { Add-Finding 'LSA' "Unsigned/invalid DLL loaded in lsass: $($_.FileName)" }
}

# ---------------------------------------------------------------- IFEO / accessibility / winlogon / safeboot
Write-Step 'IFEO, accessibility binaries, Winlogon, SafeBoot'
$ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
Get-ChildItem $ifeo -ErrorAction SilentlyContinue | ForEach-Object {
    $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
    if ($p.Debugger) { Add-Finding 'IFEO' "$($_.PSChildName) Debugger = $($p.Debugger)"; Add-Persist 'IFEO' "$($_.PSChildName)=$($p.Debugger)" }
    if ($p.GlobalFlag -band 0x200) { Add-Finding 'IFEO' "$($_.PSChildName) GlobalFlag has silent-exit monitoring (check SilentProcessExit key)" }
}
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit' -ErrorAction SilentlyContinue | ForEach-Object {
    $m = (Get-ItemProperty $_.PSPath).MonitorProcess
    if ($m) { Add-Finding 'IFEO' "SilentProcessExit\$($_.PSChildName) MonitorProcess = $m"; Add-Persist 'SilentExit' "$($_.PSChildName)=$m" }
}
$shells = @('cmd.exe', 'powershell.exe', 'explorer.exe') | ForEach-Object { (Get-FileHash "$env:SystemRoot\System32\$_" -ErrorAction SilentlyContinue).Hash }
foreach ($b in 'sethc.exe', 'utilman.exe', 'osk.exe', 'Narrator.exe', 'Magnify.exe', 'DisplaySwitch.exe', 'AtBroker.exe') {
    $f = "$env:SystemRoot\System32\$b"
    if (-not (Test-Path $f)) { continue }
    $sig = Get-AuthenticodeSignature $f
    $hash = (Get-FileHash $f).Hash
    if ($shells -contains $hash) { Add-Finding 'Access' "$b has been REPLACED with a shell (hash matches cmd/powershell/explorer)" }
    elseif ($sig.Status -ne 'Valid') { Add-Finding 'Access' "$b signature is $($sig.Status)" }
}
$wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
if ($wl.Userinit -notmatch '^C:\\Windows\\system32\\userinit\.exe,?$') { Add-Finding 'Winlogon' "Userinit = $($wl.Userinit)"; Add-Persist 'Winlogon' "Userinit=$($wl.Userinit)" }
if ($wl.Shell -ne 'explorer.exe') { Add-Finding 'Winlogon' "Shell = $($wl.Shell)"; Add-Persist 'Winlogon' "Shell=$($wl.Shell)" }
$appinit = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows').AppInit_DLLs
if ($appinit) { Add-Finding 'AppInit' "AppInit_DLLs = $appinit" }
# Note: SafeBoot\AlternateShell = cmd.exe is the Windows DEFAULT. Only anything else is suspicious.
$alt = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot' -ErrorAction SilentlyContinue).AlternateShell
if ($alt -and $alt -ne 'cmd.exe') { Add-Finding 'SafeBoot' "AlternateShell = $alt (default is cmd.exe)" }

# ---------------------------------------------------------------- Run keys + startup folders
Write-Step 'Run keys and Startup folders'
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
$runKeys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
             'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
             'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run')
Get-ChildItem HKU:\ -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$|^S-1-5-(18|19|20)$' } | ForEach-Object {
    $runKeys += "HKU:\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Run"
    $runKeys += "HKU:\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\RunOnce"
}
foreach ($k in $runKeys) {
    $p = Get-ItemProperty $k -ErrorAction SilentlyContinue
    if (-not $p) { continue }
    $p.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$' } | ForEach-Object {
        $rv = "$($_.Value)"
        $rexe = if ($rv -match '^"([^"]+)"') { $Matches[1] } elseif ($rv -match '^(.+?\.exe)') { $Matches[1] } else { ($rv -split ' ')[0] }
        if (-not (Test-TrustedMs ([Environment]::ExpandEnvironmentVariables($rexe))) -or $rv -match $BadArgs) { Add-Finding 'Run' "$k : $($_.Name) = $rv" }
        Add-Persist 'Run' "$k|$($_.Name)=$($_.Value)"
    }
}
$startDirs = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")
Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object { $startDirs += "$($_.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" }
foreach ($d in $startDirs) {
    Get-ChildItem $d -Force -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object {
        Add-Finding 'Startup' "$($_.FullName)  ($([math]::Round($_.Length/1KB)) KB)"
        Add-Persist 'Startup' $_.FullName
    }
}

# ---------------------------------------------------------------- scheduled tasks (ALL of them, including \Microsoft\)
Write-Step 'Scheduled tasks (fake tasks hide under \Microsoft\Windows\)'
$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
    $t = $_
    foreach ($a in @($t.Actions)) {
        [pscustomobject]@{
            Task    = "$($t.TaskPath)$($t.TaskName)"
            State   = "$($t.State)"
            Author  = "$($t.Author)"
            Exec    = "$($a.Execute)"
            Args    = "$($a.Arguments)"
            Trigger = (@($t.Triggers) | ForEach-Object { ($_.CimClass.CimClassName -replace 'MSFT_Task|Trigger') }) -join ','
        }
    }
}
$tasks | Export-Csv "$Run\tasks.csv" -NoTypeInformation
foreach ($t in $tasks) {
    $exe = [Environment]::ExpandEnvironmentVariables($t.Exec.Trim('"'))
    $why = @()
    $gpTask = ($t.Task -like '\Microsoft\Windows\GroupPolicy\*' -and $t.Author -match '\$$')
    if ($t.Task -like '\Microsoft\*' -and $t.Author -and $t.Author -notmatch 'Microsoft|^\$\(@|^$' -and -not $gpTask) { $why += "author '$($t.Author)' on a \Microsoft\ task" }
    $trusted = Test-TrustedMs $exe
    if ($exe -match $BadPath -and -not $trusted) { $why += 'runs from odd path' }
    if ($t.Args -match $BadArgs) { $why += 'suspicious arguments' }
    if ($exe -match '\\(mshta|wscript|cscript|bitsadmin|certutil|regsvr32)\.exe$') { $why += 'LOLBin as the program' }
    if ($exe -and -not $trusted -and ($exe -notmatch '^%|^C:\\Windows\\|^C:\\Program Files') -and $exe -match '\\') { $why += 'exe outside Windows/Program Files' }
    if ($exe -and (Test-Path $exe -ErrorAction SilentlyContinue)) {
        $s = Get-AuthenticodeSignature $exe -ErrorAction SilentlyContinue
        if ($s -and $s.Status -ne 'Valid') { $why += "unsigned" }
    }
    if ($why) { Add-Finding 'Task' "$($t.Task) [$($t.State), $($t.Trigger)] -> $($t.Exec) $($t.Args)  <= $($why -join '; ')" }
    if ($t.Task -notlike '\Microsoft\*' -or $why) { Add-Persist 'Task' "$($t.Task)=$($t.Exec) $($t.Args)" }
}

# ---------------------------------------------------------------- services
Write-Step 'Services'
$svcs = Get-WmiObject Win32_Service | Select-Object Name, DisplayName, State, StartMode, StartName, PathName
$svcs | Export-Csv "$Run\services.csv" -NoTypeInformation
foreach ($s in $svcs) {
    $path = "$($s.PathName)"
    $exe = if ($path -match '^"([^"]+)"') { $Matches[1] }
           elseif ($path -match '^(.+?\.(exe|com|bat|cmd|dll))(\s|$)') { $Matches[1] }
           else { ($path -split ' ')[0] }
    if ($path -notmatch '^"' -and $exe -match ' ' -and $exe -notmatch '^C:\\Windows\\') { Add-Finding 'Service' "$($s.Name) has an UNQUOTED path with spaces (privilege escalation): $path" }
    $bare = $path.Replace('"', '')
    $svcArgs = $bare.Substring([Math]::Min($exe.Length, $bare.Length))
    $exe = [Environment]::ExpandEnvironmentVariables($exe)
    $why = @()
    $trusted = Test-TrustedMs $exe
    if ($path -match $BadPath -and -not $trusted) { $why += 'odd path' }
    if ($svcArgs -match $BadArgs) { $why += 'suspicious arguments' }
    if ($exe -and -not $trusted -and $exe -notmatch '^(C:\\Windows\\|C:\\Program Files|\\SystemRoot\\|System32\\)' -and $exe -match '\\') { $why += 'outside Windows/Program Files' }
    if ($exe -and (Test-Path $exe -ErrorAction SilentlyContinue) -and $exe -notmatch 'svchost\.exe$') {
        $sig = Get-AuthenticodeSignature $exe -ErrorAction SilentlyContinue
        if ($sig -and $sig.Status -ne 'Valid') { $why += 'unsigned' }
    }
    if ($why) { Add-Finding 'Service' "$($s.Name) [$($s.State)/$($s.StartMode) as $($s.StartName)] -> $path  <= $($why -join '; ')" }
    if ($why -or $exe -notmatch '^C:\\Windows\\') { Add-Persist 'Service' "$($s.Name)=$path" }
}

# ---------------------------------------------------------------- WMI persistence
Write-Step 'WMI event subscriptions'
Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'SCM Event Log Filter' } |
    ForEach-Object { Add-Finding 'WMI' "EventFilter '$($_.Name)': $($_.Query)"; Add-Persist 'WMI' "Filter=$($_.Name)" }
Get-WmiObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'SCM Event Log Consumer' } |
    ForEach-Object { Add-Finding 'WMI' "Consumer '$($_.Name)' ($($_.__CLASS)): $($_.CommandLineTemplate)$($_.ScriptText)"; Add-Persist 'WMI' "Consumer=$($_.Name)" }

# ---------------------------------------------------------------- PowerShell profiles
foreach ($pf in "$env:SystemRoot\System32\WindowsPowerShell\v1.0\profile.ps1", "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1") {
    if (Test-Path $pf) { Add-Finding 'PSProfile' "$pf exists (runs for every PowerShell session)"; Add-Persist 'PSProfile' $pf }
}

# ---------------------------------------------------------------- network
ConvertTo-Json -InputObject @($Persist) | Out-File "$Run\persist.json"   # saved early; rewritten at the end
Write-Step 'Network'
$procPath = @{}
Get-Process -ErrorAction SilentlyContinue | ForEach-Object { try { $procPath[$_.Id] = $_.Path } catch {} }
$listen = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Sort-Object LocalPort -Unique |
    Select-Object LocalAddress, LocalPort, OwningProcess, @{n='Path';e={$procPath[[int]$_.OwningProcess]}}
$listen | Format-Table -AutoSize | Out-String -Width 250 | Out-File "$Run\listening.txt"
Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Sort-Object LocalPort -Unique |
    Select-Object LocalAddress, LocalPort, OwningProcess, @{n='Path';e={$procPath[[int]$_.OwningProcess]}} |
    Format-Table -AutoSize | Out-String -Width 250 | Out-File "$Run\listening-udp.txt"
Write-Good "Listening TCP ports: $((@($listen.LocalPort) | Where-Object { $_ -lt 49152 }) -join ', ')"
if ($role) {
    $allowed = @($Roles[$role].TCP) + $RemoteAccessTCP
    foreach ($l in $listen) {
        $hit = $false
        foreach ($a in $allowed) {
            if ($a -match '^(\d+)-(\d+)$') { if ($l.LocalPort -ge [int]$Matches[1] -and $l.LocalPort -le [int]$Matches[2]) { $hit = $true } }
            elseif ([int]$a -eq $l.LocalPort) { $hit = $true }
        }
        if (-not $hit -and $l.LocalAddress -notmatch '^127\.|^::1$') { Add-Finding 'Port' "Listening on $($l.LocalPort) (not in role list): $($l.Path)" }
    }
}
$est = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -notmatch '^127\.|^::1$|^0\.0\.0\.0$' } |
    Select-Object LocalPort, RemoteAddress, RemotePort, OwningProcess, @{n='Path';e={$procPath[[int]$_.OwningProcess]}}
$est | Format-Table -AutoSize | Out-String -Width 250 | Out-File "$Run\established.txt"
foreach ($e in $est) {
    if (($e.Path -match $BadPath -or ($e.Path -and $e.Path -notmatch '^C:\\(Windows|Program Files)')) -and -not (Test-TrustedMs $e.Path)) {
        Add-Finding 'C2?' "$($e.Path) -> $($e.RemoteAddress):$($e.RemotePort)"
    }
}
Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path -match $BadPath -and -not (Test-TrustedMs $_.Path) } |
    ForEach-Object { Add-Finding 'Process' "PID $($_.Id) running from odd path: $($_.Path)" }

# ---------------------------------------------------------------- Defender
Write-Step 'Defender'
try {
    $mp = Get-MpPreference -ErrorAction Stop
    foreach ($x in @($mp.ExclusionPath) + @($mp.ExclusionProcess) + @($mp.ExclusionExtension)) { if ($x) { Add-Finding 'Defender' "Exclusion: $x" } }
    if ($mp.DisableRealtimeMonitoring) { Add-Finding 'Defender' 'Real-time protection is OFF' }
    if ($mp.SubmitSamplesConsent -ne 2) { Write-Warn 'Sample submission is not "Never send" - 3-Harden.ps1 fixes this (rule 2.5)' }
} catch { Write-Warn 'Defender not available' }

# ---------------------------------------------------------------- certificates + ADCS
Write-Step 'Certificates'
Get-ChildItem Cert:\LocalMachine\My, Cert:\CurrentUser\My -ErrorAction SilentlyContinue |
    Where-Object { $_.HasPrivateKey -and ($_.EnhancedKeyUsageList.ObjectId -contains '1.3.6.1.5.5.7.3.3') } |
    ForEach-Object { Add-Finding 'Cert' "CODE-SIGNING cert WITH private key: $($_.Subject) [$($_.Thumbprint)] in $($_.PSParentPath -replace '.*::')" }
Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue | Where-Object { $_.HasPrivateKey } |
    ForEach-Object { Add-Finding 'Cert' "Trusted ROOT with private key on this box: $($_.Subject) [$($_.Thumbprint)] (normal ONLY for this host's own ADCS CA)" }
Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue | Select-Object Subject, Issuer, NotBefore, Thumbprint |
    Export-Csv "$Run\root-certs.csv" -NoTypeInformation
if (Get-Service CertSvc -ErrorAction SilentlyContinue) {
    $ef = certutil -getreg policy\EditFlags 2>$null | Out-String
    $ef | Out-File "$Run\adcs-editflags.txt"
    if ($ef -match 'EDITF_ATTRIBUTESUBJECTALTNAME2') { Add-Finding 'ADCS' 'EDITF_ATTRIBUTESUBJECTALTNAME2 is set (ESC6) - any requester can choose the SAN' }
    certutil -v -dstemplate 2>$null | Out-File "$Run\adcs-templates.txt"
    Write-Good 'ADCS templates -> adcs-templates.txt (look for ENROLLEE_SUPPLIES_SUBJECT + Client Auth + Domain Users enroll)'
}

# ---------------------------------------------------------------- firewall + WFP
Write-Step 'Firewall and WFP'
Get-NetFirewallProfile | ForEach-Object {
    if (-not $_.Enabled) { Add-Finding 'Firewall' "$($_.Name) profile is OFF" }
}
Write-Host '    (reading firewall rules - can take ~30 s)' -ForegroundColor Gray
$pfAll = @{}; Get-NetFirewallPortFilter -All -ErrorAction SilentlyContinue | ForEach-Object { $pfAll[$_.InstanceID] = $_ }
$afAll = @{}; Get-NetFirewallApplicationFilter -All -ErrorAction SilentlyContinue | ForEach-Object { $afAll[$_.InstanceID] = $_ }
Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction SilentlyContinue | Where-Object { $_.Group -ne 'Tryout' } | ForEach-Object {
    $pf = $pfAll[$_.Name]; $af = $afAll[$_.Name]
    if ($pf -and $af -and $pf.LocalPort -eq 'Any' -and $pf.Protocol -eq 'Any' -and $af.Program -eq 'Any' -and -not $af.Package) {
        Add-Finding 'Firewall' "Allow-ALL inbound rule: '$($_.DisplayName)'"
    }
}
$wfp = Join-Path $Run 'wfp-filters.xml'
netsh wfp show filters file="$wfp" | Out-Null
if (Test-Path $wfp) {
    try {
        [xml]$x = Get-Content $wfp
        $n = 0
        foreach ($f in $x.wfpdiag.filters.item) {
            $flags = @($f.flags.item) -join ','
            $name = "$($f.displayData.name)"
            if ($flags -match 'CLEAR_ACTION_RIGHT' -and $name -notmatch '^(Boot Time Filter|Port Scanning Prevention Filter|WFP Built-in|Microsoft|Windows|Default|Edge Traversal|RPC|IPsec|Teredo|Core Networking|AppContainer|Block Outbound|Allow Outbound)') {
                $n++
                Add-Finding 'WFP' "Filter '$name' action=$($f.action.type) flags=$flags weight=$($f.effectiveWeight.uint64)  (open in Tools\WFPExplorer.exe)"
            }
        }
        Write-Good "WFP filters exported to wfp-filters.xml ($n flagged)"
    } catch { Write-Warn "Could not parse WFP XML: $_" }
}

# ---------------------------------------------------------------- web shells
foreach ($root in 'C:\inetpub', 'C:\xampp\htdocs', 'C:\wamp64\www') {
    if (-not (Test-Path $root)) { continue }
    Get-ChildItem $root -Recurse -File -Include *.aspx, *.ashx, *.asp, *.php, *.jsp -ErrorAction SilentlyContinue |
        Select-String -Pattern 'eval\(|base64_decode|shell_exec|passthru|system\(|Process\.Start|cmd\.exe|Request\.Form\[.*\]\)|WScript\.Shell' -List -ErrorAction SilentlyContinue |
        ForEach-Object { Add-Finding 'Web' "Possible web shell: $($_.Path) (line $($_.LineNumber))" }
}

# ---------------------------------------------------------------- write out + compare
$Findings | Out-File "$Run\FINDINGS.txt"   # clean rewrite of what was appended live
ConvertTo-Json -InputObject @($Persist) | Out-File "$Run\persist.json"

if ($Compare) {
    Write-Step "NEW since $Compare"
    $old = @(Get-Content $Compare -Raw | ConvertFrom-Json)
    $new = @($Persist | Where-Object { $old -notcontains $_ })
    if ($new) { $new | ForEach-Object { Write-Bad $_ }; $new | Out-File "$Run\NEW-since-baseline.txt" }
    else { Write-Good 'Nothing new in autostart locations' }
    $gone = @($old | Where-Object { $Persist -notcontains $_ })
    if ($gone) { Write-Host "    Removed since baseline: $($gone.Count) item(s)" -ForegroundColor Gray }
}

Write-Host "`n$($Findings.Count) finding(s) -> $Run\FINDINGS.txt" -ForegroundColor Cyan
Write-Host "At noon: .\1-Triage.ps1 -NoBackup -Compare latest      (or -Compare `"$Run\persist.json`")" -ForegroundColor Cyan
Write-Host 'BEFORE NOON: do not remove anything from this list. Write it down, deal with it after 12:00.' -ForegroundColor Yellow
