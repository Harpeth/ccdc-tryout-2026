# CCDC Tryout – Windows kit

A trimmed, tailored version of [AllPortsTours](https://github.com/carterleehaney/AllPortsTours) for the 11/21 tryout.
Four scripts, one config file, and the tools that actually get used.

```
common.ps1        EDIT ME: team number, whitelist, protected accounts, ports per host
1-Triage.ps1      read-only: backups + hit list + baseline (safe before noon)
2-Passwords.ps1   password rotation (skips whiteteam, stops if a password filter is present)
3-Harden.ps1      logging, Defender sample submission off, SMBv1/LLMNR/WDigest off
4-Firewall.ps1    optional: role-based Windows Firewall with automatic rollback (you can do it by hand)
5-Evidence.ps1    one suspicious file/PID -> hash, strings, what starts it, connections, IR draft; -Quarantine after noon
6-Services.ps1    -Snapshot when green; then check / -Fix / -Watch: restarts services, restores shares, RDP, hosts, DNS client, IIS
Get-Tools.ps1     Sysinternals (incl. Procmon) from Microsoft + Tools\ -> C:\Tools
jumpbox/scorecheck.sh   run on the Linux jumpbox: watches every scored service, prints UP/DOWN changes
afternoon\        removal scripts (AFTER 12:00 ONLY)
original\         unmodified AllPortsTours scripts (Passwords.ps1, Harden.ps1, Check-*.ps1, Inventory.ps1) - proven at eCitadel, use as fallback
                  original\Passwords.ps1 does NOT skip whiteteam: always run it as  .\Passwords.ps1 -e whiteteam
Tools\            WFPExplorer.exe, redbaron.exe, sysmon.xml
```

## Get it onto a box

Keep the repo **public** (no token needed on the box) and keep **no passwords** in it.

From an elevated PowerShell on the Windows box:

```powershell
[Net.ServicePointManager]::SecurityProtocol='Tls12'; iwr https://github.com/<YOU>/<REPO>/archive/refs/heads/main.zip -OutFile $env:TEMP\k.zip -UseBasicParsing; Expand-Archive $env:TEMP\k.zip C:\Kit -Force; cd C:\Kit\<REPO>-main; gci -r | Unblock-File; Set-ExecutionPolicy Bypass -Scope Process -Force
```

No internet on the Windows box? Clone on the Linux jumpbox and push it over:

```bash
git clone https://github.com/<YOU>/<REPO>.git kit
smbclient //192.168.X.86/C$ -U Administrator -c 'mkdir Kit; cd Kit; prompt; recurse; lcd kit; mput *'
# or, if the box runs OpenSSH:  scp -r kit Administrator@192.168.X.86:C:/Kit
```

## Competition day

**8:20 – 9:00:** edit `common.ps1` on GitHub (web editor is fine) with your team number, the
whitelist of IPs and processes, and any accounts White Team says not to touch. Then every box pulls the same config.

Ask White Team: are password rotation, firewall changes and RunAsPPL OK before noon?

**On the jumpbox, first thing:** `chmod +x jumpbox/scorecheck.sh; ./jumpbox/scorecheck.sh <team#> <ad-domain>` and leave it running in its own terminal.

**9:00 – 12:00, per Windows box (DC first):**

| Step | Command | Notes |
|---|---|---|
| 1 | `.\Get-Tools.ps1` | |
| 2 | `.\1-Triage.ps1` | Write down the folder it prints. Read `FINDINGS.txt`. Remove nothing. |
| 3 | `.\2-Passwords.ps1` | Before step 4, so new passwords don't land in PowerShell logs. On the DC this does domain users; on member servers, local users. |
| 4 | `.\3-Harden.ps1 -Sysmon` | Add `-StopSpooler` on the DC if nothing scored prints. |
| 5 | `.\4-Firewall.ps1` | Test scored services from the jumpbox, then press **Y**. |
| 6 | `.\6-Services.ps1 -Snapshot` | Only once scorecheck is all green. Then `.\6-Services.ps1 -Fix -Watch` in a spare window. |
| 7 | Test every scored service | From the jumpbox, after every step. |

**12:00 – 4:00, hunting:**

| Step | Command |
|---|---|
| Write up anything you find | `.\5-Evidence.ps1 -Path <file>` (or `-ProcessId <pid>`) -> `C:\Backups\IR\*.md` |
| Remove it | Autoruns -> Delete the entry, then `.\5-Evidence.ps1 -Path <file> -FindCopies -Quarantine` |
| What's new since morning | `.\1-Triage.ps1 -NoBackup -Compare latest` |
| Look at everything | `C:\Tools\Autoruns64.exe`, `procexp64.exe`, `tcpview64.exe` |
| Memory beacons | `C:\Tools\redbaron.exe` (elevated). It loops forever and uses CPU: let it run a pass, read `C:\ProgramData\redbaron.log`, Ctrl+C. |
| WFP filters | `C:\Tools\WFPExplorer.exe` (triage flags candidates in `FINDINGS.txt`) |
| Password filters | `.\afternoon\Remove-PasswordFilters.ps1` (moves DLLs to `C:\stuff\bad`) |
| Sticky keys etc. | `.\afternoon\Remove-AccessibilityDebuggers-Fixed.ps1` |
| Block C2 | `.\4-Firewall.ps1 -BlockIP 1.2.3.4` (refuses whitelisted IPs) |
| Broken service | `.\afternoon\Restore-Service.ps1 -sourceFile C:\Backups\triage-<time>\services.reg -targetService <name>` |
| Bad firewall change | `.\4-Firewall.ps1 -Rollback C:\Backups\fw-<time>.wfw` |
| LSASS protection | `.\3-Harden.ps1 -RunAsPPL`, then reboot (if White Team allows) |

## Rules this kit is built around

- `whiteteam` is never changed (`ProtectedUsers` in `common.ps1`).
- No simplewall. Outbound firewall stays **allow**.
- Defender sample submission is turned **off**; never use VirusTotal options in Sysinternals (rule 2.5).
- Nothing in `1-` through `4-` deletes implants. Removal lives in `afternoon\`.

## Test tonight

If `live.sysinternals.com` is blocked on the range, copy the 9 exes named in `Get-Tools.ps1` from AllPortsTours' `SysinternalsSuite` into `Tools\` and re-run it.

None of this has been run on Windows yet. Run all four scripts once on a lab VM (a DC and a member
server) before the tryout, and fix anything that errors.
