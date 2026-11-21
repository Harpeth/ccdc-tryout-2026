<#
.SYNOPSIS
  Keep scored services up. Snapshot what "working" looks like, then check (and optionally fix) drift.
  Safe before noon: this restores services and settings, it does not remove implants.
.DESCRIPTION
  -Snapshot  saves C:\Backups\known-good\<host>.json once services are green:
               running Automatic services, SMB shares + permissions, RDP on/off + Remote Desktop Users,
               hosts file, DNS client servers, IIS sites/app pools, DNS zone record counts, firewall profiles
  -Check     (default) compares now vs snapshot and prints every difference in red
  -Fix       -Check, then puts things back: starts services + restores their start type, re-creates or
             re-permissions shares, re-enables RDP, restores hosts file and DNS client servers, starts IIS,
             unlocks locked-out domain accounts (DC). DNS record changes are only REPORTED (restore from the
             Triage zone export by hand).
.EXAMPLE
  .\6-Services.ps1 -Snapshot      # after the box is hardened and scorecheck is all green
  .\6-Services.ps1                # what changed?
  .\6-Services.ps1 -Fix           # put it back
  .\6-Services.ps1 -Fix -Watch    # check + fix every 60 s until Ctrl+C
#>
param(
    [switch]$Snapshot,
    [switch]$Fix,
    [switch]$Watch,
    [int]$Interval = 60
)
. "$PSScriptRoot\common.ps1"

$dir = Join-Path $Config.BackupDir 'known-good'
$file = Join-Path $dir "$env:COMPUTERNAME.json"
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$IsDC = Test-IsDC
if ($IsDC) { Import-Module ActiveDirectory -ErrorAction SilentlyContinue }
$hasIIS = [bool](Get-Module -ListAvailable WebAdministration)
if ($hasIIS) { Import-Module WebAdministration -ErrorAction SilentlyContinue }

# Windows services that stop by themselves after doing their job - never alert on these.
$SelfStopping = '^(sppsvc|gupdate|gupdatem|edgeupdate|edgeupdatem|MapsBroker|wuauserv|TrustedInstaller|BITS|RemoteRegistry|WaaSMedicSvc|UsoSvc|DoSvc|tiledatamodelsvc|MSiSCSI|sedsvc|WbioSrvc|CDPSvc|DiagTrack|InstallService|ClipSVC|LicenseManager|wlidsvc|TokenBroker|StorSvc|Sense|MDCoreSvc|WdNisSvc|WinDefend|SecurityHealthService|cbdhsvc.*|CDPUserSvc.*|OneSyncSvc.*|WpnUserService.*|PimIndexMaintenanceSvc.*|UnistoreSvc.*|UserDataSvc.*)$'

function Get-ServiceExe([string]$path) {
    $e = if ($path -match '^"([^"]+)"') { $Matches[1] } elseif ($path -match '^(.+?\.(exe|com))(\s|$)') { $Matches[1] } else { ($path -split ' ')[0] }
    return [Environment]::ExpandEnvironmentVariables(($e -replace '^\\SystemRoot\\', "$env:SystemRoot\" -replace '^\\\?\?\\', ''))
}

function Get-State([switch]$ForSnapshot) {
    $s = [ordered]@{}
    $s.Taken = (Get-Date).ToString('s')
    $s.Services = @()
    $s.SkippedUnsigned = @()
    if ($ForSnapshot) {
        foreach ($w in Get-WmiObject Win32_Service | Where-Object { $_.StartMode -eq 'Auto' -and $_.State -eq 'Running' -and $_.Name -notmatch $SelfStopping }) {
            $exe = Get-ServiceExe $w.PathName
            $sig = if (Test-Path $exe -ErrorAction SilentlyContinue) { (Get-AuthenticodeSignature $exe -ErrorAction SilentlyContinue).Status } else { 'Missing' }
            # Never snapshot an unsigned service binary: it could be red team's, and -Fix would bring it back.
            if ("$sig" -ne 'Valid') { $s.SkippedUnsigned += "$($w.Name) -> $($w.PathName) ($sig)"; continue }
            $s.Services += [ordered]@{ Name = $w.Name; Display = $w.DisplayName; Path = $w.PathName }
        }
    }
    $s.Shares = @(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '^(ADMIN\$|IPC\$|[A-Z]\$|print\$)$' } | ForEach-Object {
        $sh = $_
        [ordered]@{ Name = $sh.Name; Path = $sh.Path; Description = $sh.Description
            Access = @(Get-SmbShareAccess -Name $sh.Name -ErrorAction SilentlyContinue | ForEach-Object { "$($_.AccountName)|$($_.AccessControlType)|$($_.AccessRight)" }) }
    })
    $s.RdpDenied = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue).fDenyTSConnections
    $s.RdpUsers = @(net localgroup 'Remote Desktop Users' 2>$null | Select-Object -Skip 6 | Where-Object { $_ -and $_ -notmatch 'command completed' } | ForEach-Object { $_.Trim() })
    $s.HostsHash = (Get-FileHash $hostsPath -ErrorAction SilentlyContinue).Hash
    $s.HostsText = (Get-Content $hostsPath -Raw -ErrorAction SilentlyContinue)
    $s.DnsClient = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses } |
        ForEach-Object { [ordered]@{ Alias = $_.InterfaceAlias; Servers = @($_.ServerAddresses) } })
    $s.Firewall = @(Get-NetFirewallProfile | ForEach-Object { "$($_.Name)=$($_.Enabled)" })
    $s.Iis = @()
    if ($hasIIS) {
        $s.Iis += @(Get-Website -ErrorAction SilentlyContinue | ForEach-Object { "site|$($_.Name)|$($_.State)" })
        $s.Iis += @(Get-ChildItem IIS:\AppPools -ErrorAction SilentlyContinue | ForEach-Object { "pool|$($_.Name)|$($_.State)" })
    }
    $s.DnsZones = @()
    if (Get-Service DNS -ErrorAction SilentlyContinue) {
        $s.DnsZones = @(Get-DnsServerZone -ErrorAction SilentlyContinue | Where-Object { -not $_.IsAutoCreated -and $_.ZoneName -ne 'TrustAnchors' } | ForEach-Object {
            $z = $_.ZoneName
            $recs = @(Get-DnsServerResourceRecord -ZoneName $z -ErrorAction SilentlyContinue | Where-Object { $_.RecordType -in 'A', 'CNAME', 'MX', 'SRV', 'AAAA' } |
                ForEach-Object { "$($_.HostName)|$($_.RecordType)|$(($_.RecordData.PSObject.Properties | Where-Object { $_.Name -match 'IPv4Address|HostNameAlias|MailExchange|DomainName|IPv6Address' } | ForEach-Object { $_.Value }) -join ',')" })
            [ordered]@{ Zone = $z; Records = $recs }
        })
    }
    return $s
}

if ($Snapshot) {
    New-Item -ItemType Directory $dir -Force | Out-Null
    if (Test-Path $file) { Copy-Item $file "$file.$(Get-Date -Format HHmmss).old" }
    $st = Get-State -ForSnapshot
    $st | ConvertTo-Json -Depth 6 | Out-File $file -Encoding UTF8
    Write-Host "Snapshot -> $file" -ForegroundColor Cyan
    Write-Good "$($st.Services.Count) running auto services, $($st.Shares.Count) shares, $($st.DnsZones.Count) DNS zones, $($st.Iis.Count) IIS items"
    foreach ($u in $st.SkippedUnsigned) { Write-Warn "NOT in snapshot (unsigned binary - scored service or red team?): $u" }
    Write-Warn 'Only take a snapshot when scorecheck is ALL GREEN - this is what -Fix restores to.'
    Write-Warn 'After you remove implants at noon, take a NEW snapshot so -Fix never restores anything you removed.'
    exit
}

if (-not (Test-Path $file)) { Write-Bad "No snapshot yet. Get services green, then: .\6-Services.ps1 -Snapshot"; exit 1 }

function Invoke-Check {
    $good = Get-Content $file -Raw | ConvertFrom-Json
    $now = Get-State
    $issues = 0
    Write-Host "`n[$(Get-Date -Format T)] $env:COMPUTERNAME vs snapshot from $($good.Taken)" -ForegroundColor Cyan

    # services
    foreach ($sv in $good.Services) {
        $w = Get-WmiObject Win32_Service -Filter "Name='$($sv.Name)'"
        if (-not $w) { $issues++; Write-Bad "Service $($sv.Name) is GONE. Restore: .\afternoon\Restore-Service.ps1 -sourceFile <triage folder>\services.reg -targetService $($sv.Name), then reboot"; continue }
        $bad = @()
        if ($w.StartMode -ne 'Auto') { $bad += "start type $($w.StartMode)" }
        if ($w.State -ne 'Running')  { $bad += "$($w.State)" }
        if ($w.PathName -ne $sv.Path) { $bad += "BINARY PATH CHANGED to $($w.PathName)" }
        if ($bad) {
            $issues++; Write-Bad "Service $($sv.Name) ($($sv.Display)): $($bad -join ', ')"
            if ($Fix) {
                if ($w.PathName -ne $sv.Path) {
                    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$($sv.Name)" -Name ImagePath -Value $sv.Path
                    Stop-Service $sv.Name -Force -ErrorAction SilentlyContinue
                    Write-Good "  binary path restored (the changed one is an IR finding: $($w.PathName))"
                }
                Set-Service $sv.Name -StartupType Automatic -ErrorAction SilentlyContinue
                Start-Service $sv.Name -ErrorAction SilentlyContinue
                if ((Get-Service $sv.Name).Status -eq 'Running') { Write-Good "  $($sv.Name) running again" } else { Write-Bad "  $($sv.Name) won't start - check its Dependencies tab in services.msc / Event Viewer System log" }
            }
        }
    }

    # shares
    foreach ($sh in $good.Shares) {
        $cur = Get-SmbShare -Name $sh.Name -ErrorAction SilentlyContinue
        if (-not $cur) {
            $issues++; Write-Bad "Share $($sh.Name) is GONE (was $($sh.Path))"
            if ($Fix) {
                if (-not (Test-Path $sh.Path)) { New-Item -ItemType Directory $sh.Path -Force | Out-Null; Write-Warn "  folder $($sh.Path) was missing - recreated EMPTY (restore files if you have them)" }
                New-SmbShare -Name $sh.Name -Path $sh.Path -Description "$($sh.Description)" -ErrorAction SilentlyContinue | Out-Null
                Revoke-SmbShareAccess -Name $sh.Name -AccountName Everyone -Force -ErrorAction SilentlyContinue | Out-Null
                $cur = Get-SmbShare -Name $sh.Name -ErrorAction SilentlyContinue
                if ($cur) { Write-Good "  share $($sh.Name) re-created" }
            }
        } elseif ($cur.Path -ne $sh.Path) { $issues++; Write-Bad "Share $($sh.Name) now points to $($cur.Path) (was $($sh.Path)) - fix by hand: Remove-SmbShare then -Fix" }
        if ($cur) {
            $acc = @(Get-SmbShareAccess -Name $sh.Name -ErrorAction SilentlyContinue | ForEach-Object { "$($_.AccountName)|$($_.AccessControlType)|$($_.AccessRight)" })
            foreach ($a in @($sh.Access)) {
                if ($acc -notcontains $a) {
                    $issues++; Write-Bad "Share $($sh.Name) lost permission $a"
                    if ($Fix) {
                        $p = $a -split '\|'
                        if ($p[1] -eq 'Deny') { Block-SmbShareAccess -Name $sh.Name -AccountName $p[0] -Force | Out-Null }
                        else { Grant-SmbShareAccess -Name $sh.Name -AccountName $p[0] -AccessRight $p[2] -Force | Out-Null }
                        Write-Good "  restored $a"
                    }
                }
            }
            foreach ($a in $acc) {
                if (@($sh.Access) -notcontains $a) {
                    $issues++; Write-Bad "Share $($sh.Name) has NEW permission $a"
                    if ($Fix) {
                        $p = $a -split '\|'
                        if ($p[1] -eq 'Deny') { Unblock-SmbShareAccess -Name $sh.Name -AccountName $p[0] -Force | Out-Null }
                        else { Revoke-SmbShareAccess -Name $sh.Name -AccountName $p[0] -Force | Out-Null }
                        Write-Good "  removed $a"
                    }
                }
            }
        }
    }

    # RDP
    if ($good.RdpDenied -ne $now.RdpDenied) {
        $issues++; Write-Bad "RDP fDenyTSConnections changed: $($good.RdpDenied) -> $($now.RdpDenied)"
        if ($Fix) { Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' fDenyTSConnections $good.RdpDenied; Write-Good '  restored' }
    }
    foreach ($u in @($good.RdpUsers)) {
        if (@($now.RdpUsers) -notcontains $u) {
            $issues++; Write-Bad "Remote Desktop Users lost $u"
            if ($Fix) { net localgroup 'Remote Desktop Users' "$u" /add 2>&1 | Out-Null; Write-Good "  re-added $u" }
        }
    }
    foreach ($u in @($now.RdpUsers)) { if (@($good.RdpUsers) -notcontains $u) { $issues++; Write-Warn "Remote Desktop Users has NEW member $u (red team? remove after noon if so)" } }

    # hosts file
    if ($good.HostsHash -ne $now.HostsHash) {
        $issues++; Write-Bad 'hosts file changed:'
        Compare-Object @("$($good.HostsText)" -split "`r?`n") @("$($now.HostsText)" -split "`r?`n") | ForEach-Object { Write-Host "      $($_.SideIndicator) $($_.InputObject)" }
        if ($Fix) {
            Copy-Item $hostsPath (Join-Path $dir "hosts.changed.$(Get-Date -Format HHmmss)") -Force
            [IO.File]::WriteAllText($hostsPath, "$($good.HostsText)"); ipconfig /flushdns | Out-Null
            Write-Good '  hosts restored (changed copy kept in known-good\ for your IR report), DNS cache flushed'
        }
    }

    # DNS client servers
    foreach ($d in $good.DnsClient) {
        $c = (Get-DnsClientServerAddress -InterfaceAlias $d.Alias -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
        if ((@($c) -join ',') -ne (@($d.Servers) -join ',')) {
            $issues++; Write-Bad "DNS servers on '$($d.Alias)' changed: $(@($d.Servers) -join ',') -> $(@($c) -join ',')"
            if ($Fix) { Set-DnsClientServerAddress -InterfaceAlias $d.Alias -ServerAddresses @($d.Servers); ipconfig /flushdns | Out-Null; Write-Good '  restored' }
        }
    }

    # firewall profiles
    $fwNow = @($now.Firewall) -join ';'; $fwGood = @($good.Firewall) -join ';'
    if ($fwNow -ne $fwGood) {
        $issues++; Write-Bad "Firewall profiles changed: $fwGood -> $fwNow"
        if ($Fix) { foreach ($f in $good.Firewall) { $n, $e = $f -split '='; Set-NetFirewallProfile -Name $n -Enabled ([bool]::Parse($e)) }; Write-Good '  profiles restored (rules are not touched - use 4-Firewall -Rollback or netsh import)' }
    }

    # IIS
    foreach ($i in @($good.Iis)) {
        if (@($now.Iis) -notcontains $i) {
            $issues++; $kind, $name, $state = $i -split '\|'
            Write-Bad "IIS $kind '$name' is not $state any more"
            if ($Fix -and $state -eq 'Started') {
                if ($kind -eq 'site') { Start-Website -Name $name -ErrorAction SilentlyContinue } else { Start-WebAppPool -Name $name -ErrorAction SilentlyContinue }
                Write-Good "  started $kind $name"
            }
        }
    }

    # DNS records (report only)
    foreach ($z in $good.DnsZones) {
        $nz = $now.DnsZones | Where-Object { $_.Zone -eq $z.Zone }
        if (-not $nz) { $issues++; Write-Bad "DNS zone $($z.Zone) is GONE - restore from the Triage dns\ export"; continue }
        $miss = @($z.Records | Where-Object { @($nz.Records) -notcontains $_ })
        $added = @($nz.Records | Where-Object { @($z.Records) -notcontains $_ })
        foreach ($m in $miss)  { $issues++; Write-Bad "DNS $($z.Zone): missing/changed $m" }
        foreach ($a in $added) { $issues++; Write-Warn "DNS $($z.Zone): new record $a" }
        if ($miss) { Write-Host "      re-add: Add-DnsServerResourceRecordA -ZoneName $($z.Zone) -Name <host> -IPv4Address <ip>" -ForegroundColor Gray }
    }

    # locked-out accounts (DC)
    if ($IsDC) {
        $locked = @(Search-ADAccount -LockedOut -ErrorAction SilentlyContinue)
        foreach ($l in $locked) {
            $issues++; Write-Bad "Locked out: $($l.SamAccountName) (password spray?)"
            if ($Fix) { Unlock-ADAccount $l -ErrorAction SilentlyContinue; Write-Good "  unlocked $($l.SamAccountName)" }
        }
    }

    if ($issues -eq 0) { Write-Good 'Everything matches the snapshot' }
    elseif (-not $Fix) { Write-Host "$issues difference(s). Run with -Fix to restore." -ForegroundColor Yellow }
    "$(Get-Date -Format T) $issues issue(s)$(if ($Fix) { ' [fix]' })" | Out-File (Join-Path $dir "$env:COMPUTERNAME-checks.log") -Append
}

if ($Watch) {
    Write-Host "Watching every $Interval s. Ctrl+C to stop." -ForegroundColor Cyan
    while ($true) { Invoke-Check; Start-Sleep -Seconds $Interval }
} else { Invoke-Check }
