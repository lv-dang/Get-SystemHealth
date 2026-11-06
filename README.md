# Get-SystemHealth

A PowerShell script that checks the health of a Windows 10/11 PC and rates it on a scale of **1 to 100**.

It runs 12 checks (performance, storage, updates, security and stability), scores each one from 0 to 100, and combines them into one overall score with a rating, a colour-coded report and tips for anything that needs attention.

- Runs on stock **Windows PowerShell 5.1**. You don't need to install anything.
- Works on **localized Windows** (for example German), because it doesn't use performance counter names, which are translated.
- **Doesn't change anything** on the system. All checks only read information.
- Can save a **JSON or CSV report**, or return a result object for monitoring scripts.

---

## Example output

The values below are only an example.

```
==================================================================
 SYSTEM HEALTH REPORT
==================================================================
 Computer : DESKTOP-01
 OS       : Microsoft Windows 11 Pro (build 26100)
 Date     : 2026-11-06 14:05
 Admin    : yes
------------------------------------------------------------------
[OK  ] CPU load             100/100  (weight 10)
         Average load 12.4 % (5 samples). Busiest now: chrome, Teams, svchost
[OK  ] Memory                92/100  (weight 10)
         RAM used 72 % of 16 GB, commit charge 61 %
[WARN] Disk space            63/100  (weight 15)
         C: 28.4 GB free (11.9 %); D: 310.2 GB free (33.3 %)
[OK  ] Disk health          100/100  (weight 10)
         Samsung SSD 980 [SSD]: Healthy, wear 3 %, 38 C
...
------------------------------------------------------------------
 OVERALL SCORE: 84/100  [#################---]  Good
==================================================================

 Recommendations:
 - Disk space: Low disk space. Run Disk Cleanup (cleanmgr) or Storage Sense, and empty Downloads/Recycle Bin.
```

---

## Requirements

| | |
|---|---|
| OS | Windows 10 or Windows 11 |
| PowerShell | 5.1 or later (PowerShell 7 works too) |
| Rights | Runs as a normal user. **Run as Administrator** to get every check. |

---

## Quick start

1. Download `Get-SystemHealth.ps1` (or clone the repository).
2. Open PowerShell **as Administrator**.
3. Run:

```powershell
powershell -ExecutionPolicy Bypass -File .\Get-SystemHealth.ps1
```

### "File is not digitally signed" / "ist nicht digital signiert"

By default, Windows blocks scripts that were downloaded or that sit on a network drive. You can fix this in any of these ways:

```powershell
# Option 1: bypass the policy for this one run
powershell -ExecutionPolicy Bypass -File .\Get-SystemHealth.ps1

# Option 2: remove the "downloaded from the internet" mark
Unblock-File .\Get-SystemHealth.ps1
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass   # only for this window
.\Get-SystemHealth.ps1

# Option 3: if the file is on a network drive, copy it to a local drive first
Copy-Item H:\Get-SystemHealth.ps1 C:\Temp\
Unblock-File C:\Temp\Get-SystemHealth.ps1
```

If it's still blocked, run `Get-ExecutionPolicy -List`. If `MachinePolicy` or `UserPolicy` is set, the policy comes from Group Policy. In that case your IT department has to allow or sign the script.

---

## Usage

```powershell
# Normal run
.\Get-SystemHealth.ps1

# Also look for updates that aren't installed yet (needs network, can take a minute or more)
.\Get-SystemHealth.ps1 -CheckPendingUpdates

# Save a report
.\Get-SystemHealth.ps1 -ReportPath C:\Temp\health.json
.\Get-SystemHealth.ps1 -ReportPath C:\Temp\health.csv

# Use the result in another script
$r = .\Get-SystemHealth.ps1 -PassThru
if ($r.Score -lt 60) { Write-Warning "PC needs attention: $($r.Score)/100" }
```

### Parameters

| Parameter | Description |
|---|---|
| `-CheckPendingUpdates` | Asks Windows Update for updates that aren't installed yet. Critical or important ones lower the score. |
| `-ReportPath <path>` | Saves a report. Use `.json` or `.csv` as the file extension. |
| `-PassThru` | Returns the result object (`Score`, `Rating`, `Checks`, ...) to the pipeline. |

---

## What it checks

| # | Check | Weight | Details | Needs admin for |
|---|---|---|---|---|
| 1 | **CPU load** | 10 | Average of 5 samples, plus the busiest processes | - |
| 2 | **Memory** | 10 | RAM usage and commit charge (how much of RAM plus page file is in use) | - |
| 3 | **Disk space** | 15 | Free space on all internal drives. The system drive counts for 70 %. | - |
| 4 | **Disk health** | 10 | The disk's SMART health status | Wear, temperature, uncorrected read errors |
| 5 | **Windows Update** | 10 | Days since the last real update. Daily Defender definition updates don't count. | - |
| 6 | **Antivirus** | 15 | Defender: real-time protection, definition age, tamper protection. Other antivirus programs are checked through Windows Security. | - |
| 7 | **Firewall** | 10 | Domain, Private and Public profiles. Another firewall program also counts. | - |
| 8 | **Uptime / reboot** | 5 | Days since the last restart, and whether a restart is pending | - |
| 9 | **Event logs** | 10 | Critical and error events in the last 24 h. Unexpected shutdowns, blue screens and disk errors in the last 7 days. | - |
| 10 | **Core services** | 5 | 15 key services (DHCP, DNS, firewall, event log, ...) | - |
| 11 | **Security baseline** | 5 | UAC and BitLocker | Secure Boot, TPM |
| 12 | **Battery** | 5 | Laptops only: current full-charge capacity compared with the original design capacity | Often needed |

---

## How the score is calculated

1. **Each check** scores from 0 to 100. Most checks use limits that scale in between. For example, the system drive scores 100 at 20 % free space or more, and 0 at 5 % or less.
2. **The overall score** is the weighted average of all checks that could run:

   ```
   Score = sum(check score x weight) / sum(weights of checks that ran)
   ```

3. **Skipped checks** are left out. They don't lower the score. A check is skipped when it can't run, for example on a desktop with no battery, or when admin rights are missing.
4. **Serious problems cap the overall score**, so good results elsewhere can't hide them:
   - A failing disk (disk health below 50) caps the overall score at **30**
   - Missing or weak antivirus (below 50) caps it at **50**

### Ratings

| Score | Rating |
|---|---|
| 90 - 100 | Excellent |
| 75 - 89 | Good |
| 60 - 74 | Fair |
| 40 - 59 | Poor |
| 1 - 39 | Critical |

Each check also gets a status: **OK** (80 or more), **WARN** (50 - 79), **FAIL** (below 50) or **SKIP**.

---

## Customizing

- **Limits:** each check uses `Get-LinearScore <value> <good> <bad>`. Change the two numbers to make scoring stricter or looser. For example, `Get-LinearScore $age 35 90` in the Windows Update check means "full score up to 35 days, zero at 90 days".
- **Weights:** change the `-Weight` value of an `Invoke-Check` block.
- **Adding a check:** add another `Invoke-Check` block that returns a hashtable:

  ```powershell
  Invoke-Check -Name 'My check' -Weight 5 -Script {
      @{
          Score   = 100          # 0-100, or $null to skip
          Details = 'What was found'
          Advice  = 'What to do if the score is low'
          Cap     = $null        # optional: max overall score if this check fails
      }
  }
  ```

---

## Notes

- **Fast Startup:** if you use *Shut down*, Windows doesn't reset the uptime. Use *Restart* to clear the uptime warning.
- **Other antivirus programs:** if another antivirus program is installed, Defender switches to passive mode. The script then reads the status from Windows Security instead.
- **USB drives** are left out of the disk health check.
- The script only reads data. It doesn't change any settings, delete files or install updates.

---

## License

MIT - see [LICENSE](LICENSE).
