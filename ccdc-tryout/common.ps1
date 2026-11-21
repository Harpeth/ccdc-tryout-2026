# common.ps1 - EDIT THE TOP OF THIS FILE ON COMPETITION DAY.
# Every other script dot-sources this file. Nothing here changes the system.

# ============================ EDIT ME ============================
$Config = @{
    Team               = 0                    # your team number (X in 192.168.X.0/24)

    # Never change, disable, delete or lock these (rule 3.5). Add any the White Team names.
    ProtectedUsers     = @('whiteteam')

    # Accounts that scored services log in with (web app DB user, mail, etc.).
    # Password rotation skips them unless you name them with -Only.
    ServiceAccounts    = @()

    # Rule 3.6 whitelist from the White Team. Never block these IPs or delete these binaries.
    WhitelistIPs       = @()                  # e.g. '10.0.0.5','172.31.31.2'
    WhitelistProcesses = @()                  # e.g. 'salt-minion.exe','CCSclient.exe'

    # Jumpbox IP(s) for RDP/WinRM. Leave empty to allow Remote Access from anywhere
    # (safer for scoring, since "Remote Access" is a scored service).
    MgmtIPs            = @()

    BackupDir          = 'C:\Backups'
    ToolsDir           = 'C:\Tools'
}

# Inbound ports to allow per host. Matched against the hostname with -match,
# because NetBIOS names cut off at 15 chars (TEAM07-CERTIFIED -> TEAM07-CERTIFIE).
$Roles = [ordered]@{
    'ctrl'   = @{ Desc = 'DC: ADDS, LDAP, DNS';        TCP = @('53','88','135','389','445','464','636','3268','3269','9389','49152-65535'); UDP = @('53','88','123','389','464') }
    'certif' = @{ Desc = 'ADCS + file sharing';         TCP = @('80','135','443','445','49152-65535');                                     UDP = @() }
    'lookup' = @{ Desc = 'DNS';                         TCP = @('53');                                                                     UDP = @('53') }
    'comms'  = @{ Desc = 'Mail';                        TCP = @('25','80','110','143','443','465','587','993','995');                      UDP = @() }
    'chris'  = @{ Desc = 'Device management (verify!)'; TCP = @('80','443','8530','8531');                                                 UDP = @() }
    'sting'  = @{ Desc = 'Web + DB';                    TCP = @('80','443','1433','3306');                                                 UDP = @() }
    'whale'  = @{ Desc = 'Web + DB + credentials';      TCP = @('80','443','1433','3306','8080','8443');                                   UDP = @() }
    'andie'  = @{ Desc = 'Orchestration/HTTP';          TCP = @('80','443','8080','8443');                                                 UDP = @() }
}
# Remote Access is scored on every host.
$RemoteAccessTCP = @('22','3389','5985','5986')
# =================================================================

$ErrorActionPreference = 'Continue'

function Test-Admin {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-IsDC {
    try { return ((Get-WmiObject Win32_OperatingSystem).ProductType -eq 2) } catch { return $false }
}

function Get-HostRole {
    foreach ($k in $Roles.Keys) {
        if ($env:COMPUTERNAME -match $k) { return $k }
    }
    return $null
}

function New-RunDir([string]$Name) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $dir = Join-Path $Config.BackupDir "$Name-$stamp"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    return $dir
}

function Write-Step([string]$Text)  { Write-Host "`n[*] $Text" -ForegroundColor Cyan }
function Write-Good([string]$Text)  { Write-Host "    [+] $Text" -ForegroundColor Green }
function Write-Warn([string]$Text)  { Write-Host "    [!] $Text" -ForegroundColor Yellow }
function Write-Bad([string]$Text)   { Write-Host "    [X] $Text" -ForegroundColor Red }

# Values Windows ships with. Anything else in these LSA keys deserves a look.
$KnownLsa = @{
    'Notification Packages'   = @('scecli', 'rassfm')
    'Authentication Packages' = @('msv1_0')
    'Security Packages'       = @('', '""', 'kerberos', 'msv1_0', 'schannel', 'wdigest', 'tspkg', 'pku2u', 'cloudap')
    'SecurityProviders'       = @('credssp.dll')
}

# Returns the LSA plug-in DLLs that are not on the known-good list.
function Get-LsaFindings {
    $out = @()
    $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
    foreach ($name in 'Notification Packages', 'Authentication Packages', 'Security Packages') {
        foreach ($v in @($lsa.$name)) {
            if ($null -eq $v) { continue }
            $val = "$v".Trim()
            if ($KnownLsa[$name] -notcontains $val) {
                $out += [pscustomobject]@{ Key = "Lsa\$name"; Value = $val }
            }
        }
    }
    $sp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders' -ErrorAction SilentlyContinue).SecurityProviders
    if ($sp) {
        foreach ($v in ($sp -split ',')) {
            $val = $v.Trim()
            if ($val -and ($KnownLsa['SecurityProviders'] -notcontains $val)) {
                $out += [pscustomobject]@{ Key = 'SecurityProviders'; Value = $val }
            }
        }
    }
    return $out
}

if (-not (Test-Admin)) {
    Write-Host '[X] Run this from an elevated PowerShell (Run as Administrator).' -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $Config.BackupDir)) { New-Item -ItemType Directory -Path $Config.BackupDir -Force | Out-Null }
