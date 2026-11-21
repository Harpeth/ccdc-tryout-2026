<#
.SYNOPSIS
  Windows Firewall for this host's role (ports come from $Roles in common.ps1).
  - Backs up the current firewall first
  - Inbound: block by default, allow the role's ports + Remote Access + ping + whitelisted IPs
  - Outbound: left at ALLOW. At eCitadel, blocking outbound cut off the scoring agent.
  - Dead-man switch: if you don't press Y within 90 seconds (for example because the change
    cut off your Guac session), the old firewall is restored automatically.
  All rules it creates are in the group 'Tryout', so re-running replaces them cleanly.
.EXAMPLE
  .\4-Firewall.ps1                      # uses the role matched from the hostname
  .\4-Firewall.ps1 -Role ctrl           # force a role
  .\4-Firewall.ps1 -ExtraTCP 8081,9000  # add ports you found listening for a scored service
  .\4-Firewall.ps1 -Rollback C:\Backups\fw-....wfw
  .\4-Firewall.ps1 -BlockIP 10.10.20.114   # after noon: block a C2 IP (refuses whitelisted IPs)
#>
param(
    [string]$Role,
    [string[]]$ExtraTCP = @(),
    [string[]]$ExtraUDP = @(),
    [string]$Rollback,
    [string[]]$BlockIP,
    [int]$Timeout = 90
)
. "$PSScriptRoot\common.ps1"

if ($Rollback) {
    netsh advfirewall import "$Rollback" | Out-Null
    Write-Good "Restored $Rollback"
    exit
}

if ($BlockIP) {
    foreach ($ip in $BlockIP) {
        if ($Config.WhitelistIPs -contains $ip) { Write-Bad "$ip is on the White Team whitelist - NOT blocking it"; continue }
        New-NetFirewallRule -DisplayName "Tryout BLOCK $ip in" -Group 'Tryout' -Direction Inbound -RemoteAddress $ip -Action Block | Out-Null
        New-NetFirewallRule -DisplayName "Tryout BLOCK $ip out" -Group 'Tryout' -Direction Outbound -RemoteAddress $ip -Action Block | Out-Null
        Write-Good "Blocked $ip both directions (put this in your IR report)"
    }
    exit
}

if ($Role) { $Role = $Role.TrimStart('-').ToLower() }
if (-not $Role) { $Role = Get-HostRole }
if (-not $Role -or -not $Roles.Contains($Role)) {
    Write-Bad "No role for $env:COMPUTERNAME. Use -Role with one of: $($Roles.Keys -join ', ')"
    exit 1
}
$tcp = @($Roles[$Role].TCP) + @($ExtraTCP) | Where-Object { $_ } | Select-Object -Unique
$udp = @($Roles[$Role].UDP) + @($ExtraUDP) | Where-Object { $_ } | Select-Object -Unique
$mgmt = if ($Config.MgmtIPs) { $Config.MgmtIPs } else { 'Any' }

Write-Host "Role: $Role ($($Roles[$Role].Desc))" -ForegroundColor Cyan
Write-Host "  TCP in : $($tcp -join ', ')"
Write-Host "  UDP in : $($udp -join ', ')"
Write-Host "  Remote : $($RemoteAccessTCP -join ', ') from $mgmt"
Write-Host "  Allow-all from whitelist: $(if ($Config.WhitelistIPs) { $Config.WhitelistIPs -join ', ' } else { '(none set)' })"

# Show listening ports this would NOT allow, so you can catch a scored service you forgot.
$covered = { param($p) foreach ($a in $tcp + $RemoteAccessTCP) { if ($a -match '^(\d+)-(\d+)$') { if ($p -ge [int]$Matches[1] -and $p -le [int]$Matches[2]) { return $true } } elseif ([int]$a -eq $p) { return $true } }; return $false }
$missing = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalAddress -notmatch '^127\.|^::1$' } |
    Sort-Object LocalPort -Unique | Where-Object { -not (& $covered $_.LocalPort) }
foreach ($m in $missing) {
    $p = (Get-Process -Id $m.OwningProcess -ErrorAction SilentlyContinue).Path
    Write-Warn "Listening on TCP $($m.LocalPort) but NOT allowed: $p  (scored? re-run with -ExtraTCP $($m.LocalPort))"
}
$go = Read-Host "`nApply? (y/n)"
if ($go -ne 'y') { exit }

$backup = Join-Path $Config.BackupDir "fw-$(Get-Date -Format 'HHmmss').wfw"
netsh advfirewall export "$backup" | Out-Null
Write-Good "Backup: $backup"

Get-NetFirewallRule -Group 'Tryout' -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -notlike 'Tryout BLOCK*' } | Remove-NetFirewallRule
$r = @{ Group = 'Tryout'; Direction = 'Inbound'; Action = 'Allow'; Profile = 'Any' }
if ($tcp) { New-NetFirewallRule @r -DisplayName "Tryout $Role TCP" -Protocol TCP -LocalPort $tcp | Out-Null }
if ($udp) { New-NetFirewallRule @r -DisplayName "Tryout $Role UDP" -Protocol UDP -LocalPort $udp | Out-Null }
New-NetFirewallRule @r -DisplayName 'Tryout Remote Access' -Protocol TCP -LocalPort $RemoteAccessTCP -RemoteAddress $mgmt | Out-Null
New-NetFirewallRule @r -DisplayName 'Tryout ICMPv4 echo' -Protocol ICMPv4 -IcmpType 8 | Out-Null
if ($Config.WhitelistIPs) { New-NetFirewallRule @r -DisplayName 'Tryout White Team whitelist' -RemoteAddress $Config.WhitelistIPs | Out-Null }

Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -LogBlocked True -LogFileName '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'
Write-Good 'Firewall on: inbound default block, outbound allow'

# Note: rules that existed before this script (including any red team "allow all" rule) are still active.
$others = Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow | Where-Object { $_.Group -ne 'Tryout' }
Write-Warn "$(@($others).Count) other inbound ALLOW rules still enabled. After noon, review them: Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow | ? Group -ne 'Tryout' | select DisplayName,Group"

# ---- dead-man switch
Write-Host "`nTest scored services from the jumpbox NOW. Press Y within $Timeout s to keep the new firewall." -ForegroundColor Yellow
$keep = $false
$deadline = (Get-Date).AddSeconds($Timeout)
try {
    while ((Get-Date) -lt $deadline) {
        if ([Console]::KeyAvailable) {
            $k = [Console]::ReadKey($true)
            if ($k.Key -eq 'Y') { $keep = $true; break }
            if ($k.Key -eq 'N') { break }
        }
        Start-Sleep -Milliseconds 250
    }
} catch {
    # No console (ISE / remoting): fall back to a plain prompt.
    $keep = ((Read-Host 'Keep? (y/n)') -eq 'y')
}
if ($keep) {
    Write-Good 'Kept.'
} else {
    netsh advfirewall import "$backup" | Out-Null
    Write-Bad "Not confirmed - restored $backup"
}
