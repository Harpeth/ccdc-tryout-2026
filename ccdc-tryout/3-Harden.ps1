<#
.SYNOPSIS
  Low-risk hardening. Based on AllPortsTours Harden.ps1, changed for this tryout.
  Default run changes only things that should not break scored services:
    - Defender: sample submission OFF (rule 2.5: nothing leaves the environment), real-time ON
    - PowerShell script block + module logging, transcripts to C:\Backups\pslogs (Administrators only)
    - Process creation auditing with command lines, plus the audit categories you used at eCitadel
    - SMBv1 off, LLMNR off, WDigest plaintext caching off, Guest disabled, UAC on
    - DC only: LDAP diagnostic logging
  Riskier items are opt-in switches. Ask White Team before -RunAsPPL (it needs a reboot).
.EXAMPLE
  .\3-Harden.ps1
  .\3-Harden.ps1 -Sysmon               # also install Sysmon with Tools\sysmon.xml (run Get-Tools.ps1 first)
  .\3-Harden.ps1 -StopSpooler          # DC only, if nothing scored prints
  .\3-Harden.ps1 -RunAsPPL             # protect LSASS from injection (WildWest injector.exe); REBOOT needed
  .\3-Harden.ps1 -NLA                  # require NLA on RDP - test that Guac still connects!
#>
param(
    [switch]$Sysmon,
    [switch]$StopSpooler,
    [switch]$RunAsPPL,
    [switch]$NLA
)
. "$PSScriptRoot\common.ps1"
$IsDC = Test-IsDC
$reboot = @()

function Set-Reg([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord') {
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
}

Write-Step 'Defender'
try {
    Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction Stop      # 2 = never send samples
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
    Write-Good 'Sample submission = Never send; real-time protection on'
    $mp = Get-MpPreference
    $ex = @($mp.ExclusionPath) + @($mp.ExclusionProcess) + @($mp.ExclusionExtension) | Where-Object { $_ }
    if ($ex) { Write-Warn "Defender exclusions present (red team adds these): $($ex -join ', ')" }
} catch { Write-Warn 'Defender not present or tamper-protected' }

Write-Step 'PowerShell logging'
$ps = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
Set-Reg "$ps\ScriptBlockLogging" 'EnableScriptBlockLogging' 1
Set-Reg "$ps\ModuleLogging" 'EnableModuleLogging' 1
Set-Reg "$ps\ModuleLogging\ModuleNames" '*' '*' 'String'
$tdir = Join-Path $Config.BackupDir 'pslogs'
New-Item -ItemType Directory $tdir -Force | Out-Null
icacls $tdir /inheritance:r /grant:r 'BUILTIN\Administrators:(OI)(CI)F' 'NT AUTHORITY\SYSTEM:(OI)(CI)F' 'Everyone:(CI)(WD,AD)' | Out-Null
Set-Reg "$ps\Transcription" 'EnableTranscripting' 1
Set-Reg "$ps\Transcription" 'EnableInvocationHeader' 1
Set-Reg "$ps\Transcription" 'OutputDirectory' $tdir 'String'
Write-Good "Script block (event 4104), module logging, transcripts -> $tdir"

Write-Step 'Audit policy'
Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 1
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy' 1
foreach ($sub in 'Process Creation', 'Logon', 'Account Lockout', 'User Account Management', 'Security Group Management',
                 'Credential Validation', 'Sensitive Privilege Use', 'Other Object Access Events', 'Security System Extension') {
    auditpol /set /subcategory:"$sub" /success:enable /failure:enable | Out-Null
}
if ($IsDC) {
    foreach ($sub in 'Directory Service Changes', 'Directory Service Access', 'Kerberos Authentication Service', 'Kerberos Service Ticket Operations') {
        auditpol /set /subcategory:"$sub" /success:enable /failure:enable | Out-Null
    }
}
Write-Good 'Process creation (4688 with command line), logons, account and group changes, new services/tasks'

Write-Step 'Protocol and credential hardening'
try { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop; Write-Good 'SMBv1 server off' }
catch { Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1' 0; Write-Good 'SMBv1 off (registry)'; $reboot += 'SMBv1' }
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0
Write-Good 'LLMNR off'
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0
Write-Good 'WDigest plaintext credential caching off'
if ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA -ne 1) {
    Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA' 1
    $reboot += 'UAC'
    Write-Good 'UAC turned back on'
}
if ($IsDC) {
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    Disable-ADAccount -Identity Guest -ErrorAction SilentlyContinue
} else {
    Disable-LocalUser -Name Guest -ErrorAction SilentlyContinue
}
Write-Good 'Guest disabled'

if ($IsDC) {
    Write-Step 'DC: LDAP diagnostic logging'
    $d = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics'
    Set-Reg $d '15 Field Engineering' 5
    Set-Reg $d '16 LDAP Interface Events' 2
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'Expensive Search Results Threshold' 1
    Write-Good 'LDAP queries logged to Directory Service log (event 1644)'
}

if ($StopSpooler) {
    Write-Step 'Print Spooler'
    if ($IsDC) { Stop-Service Spooler -Force -ErrorAction SilentlyContinue; Set-Service Spooler -StartupType Disabled; Write-Good 'Spooler stopped and disabled' }
    else { Write-Warn 'Not a DC - left Spooler alone' }
}

if ($NLA) {
    Write-Step 'RDP NLA'
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1
    Write-Good 'NLA required. Open a NEW Guac session now to confirm you can still get in.'
}

if ($RunAsPPL) {
    Write-Step 'LSASS protection (RunAsPPL)'
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL' 1
    $reboot += 'RunAsPPL'
    Write-Good 'Set. After reboot, unsigned DLLs (password filters, SSPs, injected DLLs) cannot load into LSASS.'
}

if ($Sysmon) {
    Write-Step 'Sysmon'
    $exe = Join-Path $Config.ToolsDir 'Sysmon64.exe'
    $cfg = Join-Path $PSScriptRoot 'Tools\sysmon.xml'
    if (-not (Test-Path $exe)) { Write-Bad "No $exe - run .\Get-Tools.ps1 first" }
    elseif (Get-Service Sysmon64 -ErrorAction SilentlyContinue) { & $exe -c $cfg | Out-Null; Write-Good 'Sysmon already installed - config updated' }
    else { & $exe -accepteula -i $cfg | Out-Null; Write-Good 'Sysmon installed (log: Microsoft-Windows-Sysmon/Operational)' }
}

Write-Host ''
if ($reboot) { Write-Warn "Needs a reboot to take effect: $($reboot -join ', '). Reboot when it costs the least uptime." }
Write-Host 'Done. Test every scored service from the jumpbox now.' -ForegroundColor Cyan
