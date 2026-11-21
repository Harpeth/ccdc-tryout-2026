<#
.SYNOPSIS
  Rotate passwords. Based on AllPortsTours Passwords.ps1, changed for this tryout:
    - never touches whiteteam (or anything in ProtectedUsers / ServiceAccounts in common.ps1)
    - refuses to run if an unknown LSA password filter is present (it would leak every new password)
    - prompts for the admin password as a SecureString, so it never shows up in PowerShell logs
    - skips krbtgt unless you ask (-IncludeKrbtgt)
    - saves the new passwords to C:\Backups\passwords-<host>-<time>.csv, readable by Administrators only
  On a DC it changes domain users. On any other box it changes local users.
.EXAMPLE
  .\2-Passwords.ps1                         # admins get the password you type, everyone else gets a random one
  .\2-Passwords.ps1 -Same                   # everyone gets the password you type
  .\2-Passwords.ps1 -Only Administrator     # just these accounts
  .\2-Passwords.ps1 -Exclude bob,alice
#>
param(
    [string[]]$Only,
    [string[]]$Exclude,
    [switch]$Same,
    [switch]$IncludeKrbtgt,
    [switch]$Force
)
. "$PSScriptRoot\common.ps1"

# 1. Password filter check (WildWest: passwd.dll sent every change to a Discord webhook)
$lsa = Get-LsaFindings | Where-Object { $_.Key -eq 'Lsa\Notification Packages' }
if ($lsa -and -not $Force) {
    Write-Bad "Unknown password filter(s) in Notification Packages: $($lsa.Value -join ', ')"
    Write-Bad 'Changing passwords now would send them to red team. Remove the filter first (after noon, afternoon\Remove-PasswordFilters.ps1),'
    Write-Bad 'or ask White Team. Re-run with -Force to change them anyway.'
    exit 1
}

if ($Only -and $Exclude) { Write-Bad 'Use -Only or -Exclude, not both.'; exit 1 }

$skip = @($Config.ProtectedUsers) + @($Config.ServiceAccounts) + @($Exclude) + @('DefaultAccount', 'WDAGUtilityAccount', 'Guest')
if (-not $IncludeKrbtgt) { $skip += 'krbtgt' }
$skip = $skip | Where-Object { $_ } | ForEach-Object { $_.ToLower() }

$sec = Read-Host 'Password for admin accounts' -AsSecureString
$sec2 = Read-Host 'Confirm' -AsSecureString
$b1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
$b2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec2))
if ($b1 -ne $b2 -or $b1.Length -lt 12) { Write-Bad 'Passwords did not match or are shorter than 12 characters.'; exit 1 }

Add-Type -AssemblyName System.Web
function New-RandomPassword {
    do { $p = [System.Web.Security.Membership]::GeneratePassword(14, 3) } while ($p -match '[,;:|''"`iIlLoO0]')
    return $p + '7!'
}

$results = @()
$IsDC = Test-IsDC

if ($IsDC) {
    Import-Module ActiveDirectory
    if ((Get-WmiObject Win32_ComputerSystem).DomainRole -eq 4) { Write-Warn 'This is a secondary DC. Run this on the primary DC only.'; exit }
    $admins = @()
    foreach ($g in 'Domain Admins', 'Enterprise Admins', 'Administrators') {
        $admins += Get-ADGroupMember $g -Recursive -ErrorAction SilentlyContinue | Where-Object objectClass -eq 'user' | Select-Object -ExpandProperty SamAccountName
    }
    $users = Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName
    foreach ($u in $users) {
        if ($Only -and ($Only -notcontains $u)) { continue }
        if ($skip -contains $u.ToLower()) { Write-Host "    [-] skipped $u" -ForegroundColor Gray; continue }
        $isAdmin = $admins -contains $u
        $pw = if ($isAdmin -or $Same) { $b1 } else { New-RandomPassword }
        try {
            Set-ADAccountPassword -Identity $u -Reset -NewPassword (ConvertTo-SecureString $pw -AsPlainText -Force) -ErrorAction Stop
            Write-Good "$u$(if ($isAdmin) { ' (admin)' })"
            $results += [pscustomobject]@{ User = $u; Admin = $isAdmin; Password = $pw }
        } catch { Write-Bad "$u : $($_.Exception.Message)" }
    }
} else {
    # 'net localgroup' instead of Get-LocalGroupMember, which breaks on orphaned SIDs
    $admins = @(net localgroup Administrators 2>$null | Select-Object -Skip 6 | Where-Object { $_ -and $_ -notmatch 'command completed' } | ForEach-Object { ($_ -split '\\')[-1].Trim() })
    foreach ($lu in Get-LocalUser) {
        $u = $lu.Name
        if ($Only -and ($Only -notcontains $u)) { continue }
        if ($skip -contains $u.ToLower()) { Write-Host "    [-] skipped $u" -ForegroundColor Gray; continue }
        $isAdmin = ($admins -contains $u) -or ($lu.SID -like '*-500')
        $pw = if ($isAdmin -or $Same) { $b1 } else { New-RandomPassword }
        try {
            Set-LocalUser -Name $u -Password (ConvertTo-SecureString $pw -AsPlainText -Force) -ErrorAction Stop
            Write-Good "$u$(if ($isAdmin) { ' (admin)' })"
            $results += [pscustomobject]@{ User = $u; Admin = $isAdmin; Password = $pw }
        } catch { Write-Bad "$u : $($_.Exception.Message)" }
    }
}

$out = Join-Path $Config.BackupDir "passwords-$env:COMPUTERNAME-$(Get-Date -Format 'HHmmss').csv"
$results | Export-Csv $out -NoTypeInformation
icacls $out /inheritance:r /grant:r 'BUILTIN\Administrators:F' 'NT AUTHORITY\SYSTEM:F' | Out-Null
Write-Host "`n$($results.Count) password(s) changed -> $out (Administrators only)" -ForegroundColor Cyan
Write-Host 'Random passwords are only in that file. If an inject asks for them (password change request), use that file.' -ForegroundColor Yellow
Write-Host 'Now test every scored service from the jumpbox - a service account you missed will show up here first.' -ForegroundColor Yellow
$b1 = $null; $b2 = $null
