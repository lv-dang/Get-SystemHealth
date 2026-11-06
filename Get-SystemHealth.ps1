<#
.SYNOPSIS
    Checks the health of a Windows 10/11 system and rates it from 1 to 100.

.DESCRIPTION
    Runs a set of weighted checks (CPU, memory, disk space, disk health, Windows
    Update, antivirus, firewall, uptime/pending reboot, event logs, core services,
    security baseline, battery) and combines them into one score from 1 to 100.

    Each check gets its own score from 0 to 100. The overall score is the weighted
    average of all checks that could run. Checks that cannot run (for example
    because the script is not elevated) are skipped and left out of the average.
    A few serious problems (failing disk, no antivirus) cap the overall score,
    so they cannot be hidden by good results elsewhere.

    Run as Administrator for the most complete result (disk SMART counters,
    Secure Boot, TPM, battery wear).

.PARAMETER CheckPendingUpdates
    Also asks Windows Update for updates that are not installed yet.
    This needs network access and can take a minute or more.

.PARAMETER ReportPath
    Optional path for a report file. Use .json or .csv as the extension.

.PARAMETER PassThru
    Returns the result object to the pipeline (useful for scripting / monitoring).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Get-SystemHealth.ps1

.EXAMPLE
    .\Get-SystemHealth.ps1 -CheckPendingUpdates -ReportPath C:\Temp\health.json

.EXAMPLE
    $r = .\Get-SystemHealth.ps1 -PassThru; if ($r.Score -lt 60) { 'Needs attention' }
#>

#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$CheckPendingUpdates,
    [string]$ReportPath,
    [switch]$PassThru
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

$Results = New-Object System.Collections.Generic.List[object]

function Get-LinearScore {
    # 100 at (or beyond) $Good, 0 at (or beyond) $Bad, linear in between.
    # Works in both directions (lower-is-better and higher-is-better).
    param([double]$Value, [double]$Good, [double]$Bad)
    if ($Good -eq $Bad) { if ($Value -eq $Good) { return 100 } else { return 0 } }
    $t = ($Value - $Bad) / ($Good - $Bad)
    if ($t -ge 1) { return 100 }
    if ($t -le 0) { return 0 }
    return [math]::Round($t * 100, 1)
}

function Limit-Score {
    param([double]$Value)
    if ($Value -lt 0) { return 0 }
    if ($Value -gt 100) { return 100 }
    return [math]::Round($Value, 1)
}

function Invoke-Check {
    # Runs one check. The script block returns a hashtable with:
    #   Score   (0-100, or $null to skip)
    #   Details (text)
    #   Advice  (text shown when the score is low, optional)
    #   Cap     (optional max overall score if this check fails badly)
    param(
        [string]$Name,
        [int]$Weight,
        [scriptblock]$Script
    )
    Write-Progress -Activity 'Checking system health' -Status $Name
    try {
        $r = & $Script | Select-Object -Last 1
        if (-not ($r -is [hashtable])) { throw 'Check returned no result.' }
    }
    catch {
        $r = @{ Score = $null; Details = "Could not run: $($_.Exception.Message)" }
    }

    $score = $null
    if ($null -ne $r.Score) { $score = Limit-Score $r.Score }

    if ($null -eq $score) { $status = 'SKIP' }
    elseif ($score -ge 80) { $status = 'OK' }
    elseif ($score -ge 50) { $status = 'WARN' }
    else { $status = 'FAIL' }

    $Results.Add([pscustomobject]@{
        Check   = $Name
        Weight  = $Weight
        Score   = $score
        Status  = $status
        Details = [string]$r.Details
        Advice  = [string]$r.Advice
        Cap     = $r.Cap
    })
}

# ---------------------------------------------------------------------------
# System info
# ---------------------------------------------------------------------------

$os = Get-CimInstance Win32_OperatingSystem
$build = [int]$os.BuildNumber
if ($os.Caption -notmatch 'Windows (10|11)') {
    Write-Warning "This script is made for Windows 10/11. Detected: $($os.Caption). Results may be incomplete."
}

# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

# 1. CPU load ---------------------------------------------------------------
Invoke-Check -Name 'CPU load' -Weight 10 -Script {
    # WMI performance class instead of Get-Counter, because counter names are
    # localized (e.g. German Windows) and Get-Counter would fail there.
    $samples = foreach ($i in 1..5) {
        (Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'").PercentProcessorTime
        Start-Sleep -Milliseconds 800
    }
    $avg = [math]::Round(($samples | Measure-Object -Average).Average, 1)

    $top = Get-CimInstance Win32_PerfFormattedData_PerfProc_Process |
        Where-Object { $_.Name -notin '_Total', 'Idle' } |
        Sort-Object PercentProcessorTime -Descending | Select-Object -First 3 |
        ForEach-Object { $_.Name }

    @{
        Score   = Get-LinearScore $avg 50 95
        Details = "Average load $avg % (5 samples). Busiest now: $($top -join ', ')"
        Advice  = 'CPU is under heavy load. Check Task Manager for processes using a lot of CPU.'
    }
}

# 2. Memory -----------------------------------------------------------------
Invoke-Check -Name 'Memory' -Weight 10 -Script {
    $o = Get-CimInstance Win32_OperatingSystem
    $totalGB = [math]::Round($o.TotalVisibleMemorySize / 1MB, 1)
    $usedPct = [math]::Round((1 - $o.FreePhysicalMemory / $o.TotalVisibleMemorySize) * 100, 1)
    $commitPct = [math]::Round((1 - $o.FreeVirtualMemory / $o.TotalVirtualMemorySize) * 100, 1)

    $s = [math]::Min((Get-LinearScore $usedPct 70 95), (Get-LinearScore $commitPct 80 98))
    @{
        Score   = $s
        Details = "RAM used $usedPct % of $totalGB GB, commit charge $commitPct %"
        Advice  = 'Memory is nearly full. Close programs you are not using, or add more RAM.'
    }
}

# 3. Disk space -------------------------------------------------------------
Invoke-Check -Name 'Disk space' -Weight 15 -Script {
    $sys = $env:SystemDrive
    $disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | Where-Object { $_.Size -gt 0 })
    if ($disks.Count -eq 0) { throw 'No fixed drives found.' }

    $parts = @()
    $sysScore = $null
    $otherScores = @()
    foreach ($d in $disks) {
        $freeGB = [math]::Round($d.FreeSpace / 1GB, 1)
        $freePct = [math]::Round($d.FreeSpace / $d.Size * 100, 1)
        $parts += "$($d.DeviceID) $freeGB GB free ($freePct %)"
        if ($d.DeviceID -eq $sys) {
            $sysScore = [math]::Min((Get-LinearScore $freePct 20 5), (Get-LinearScore $freeGB 30 5))
        }
        else {
            $otherScores += Get-LinearScore $freePct 15 3
        }
    }
    if ($null -eq $sysScore) { $sysScore = 100 }

    if ($otherScores.Count -gt 0) {
        $minOther = ($otherScores | Measure-Object -Minimum).Minimum
        $s = 0.7 * $sysScore + 0.3 * $minOther
    }
    else { $s = $sysScore }

    @{
        Score   = $s
        Details = $parts -join '; '
        Advice  = 'Low disk space. Run Disk Cleanup (cleanmgr) or Storage Sense, and empty Downloads/Recycle Bin.'
    }
}

# 4. Disk health (SMART) ----------------------------------------------------
Invoke-Check -Name 'Disk health' -Weight 10 -Script {
    $pds = @(Get-PhysicalDisk | Where-Object { "$($_.BusType)" -ne 'USB' })
    if ($pds.Count -eq 0) { throw 'No internal physical disks found.' }

    $scores = @()
    $parts = @()
    foreach ($pd in $pds) {
        $h = "$($pd.HealthStatus)"
        switch ($h) {
            'Healthy'   { $s = 100 }
            'Warning'   { $s = 40 }
            'Unhealthy' { $s = 0 }
            default     { $s = 70 }
        }
        $info = "$($pd.FriendlyName) [$($pd.MediaType)]: $h"

        if ($IsAdmin) {
            $rc = $pd | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue
            if ($rc) {
                if ($null -ne $rc.Wear -and $rc.Wear -gt 0) {
                    $info += ", wear $($rc.Wear) %"
                    if ($rc.Wear -ge 90) { $s = [math]::Min($s, 40) }
                    elseif ($rc.Wear -ge 70) { $s = [math]::Min($s, 75) }
                }
                if ($null -ne $rc.Temperature -and $rc.Temperature -gt 0) {
                    $info += ", $($rc.Temperature) C"
                    if ($rc.Temperature -ge 65) { $s = [math]::Min($s, 70) }
                }
                if ($rc.ReadErrorsUncorrected -gt 0) {
                    $info += ", $($rc.ReadErrorsUncorrected) uncorrected read errors"
                    $s = [math]::Min($s, 50)
                }
            }
        }
        $scores += $s
        $parts += $info
    }
    $min = ($scores | Measure-Object -Minimum).Minimum
    $cap = $null
    if ($min -lt 50) { $cap = 30 }

    $extra = ''
    if (-not $IsAdmin) { $extra = ' (run as admin for wear/temperature)' }
    @{
        Score   = $min
        Details = ($parts -join '; ') + $extra
        Advice  = 'A disk reports problems. Back up your data NOW and plan to replace the drive.'
        Cap     = $cap
    }
}

# 5. Windows Update ---------------------------------------------------------
Invoke-Check -Name 'Windows Update' -Weight 10 -Script {
    $lastDate = $null

    # Update history (excluding Defender definition updates, which install daily)
    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $count = $searcher.GetTotalHistoryCount()
        if ($count -gt 0) {
            $hist = $searcher.QueryHistory(0, [math]::Min($count, 300))
            $last = $hist | Where-Object {
                $_.Operation -eq 1 -and $_.ResultCode -eq 2 -and
                $_.Title -notmatch 'Security Intelligence|Definition Update|KB2267602|KB4052623|Antimalware'
            } | Sort-Object Date -Descending | Select-Object -First 1
            if ($last) { $lastDate = $last.Date.ToLocalTime() }
        }
    }
    catch { }

    # Installed hotfixes as a second source
    $hf = Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.InstalledOn } |
        Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($hf -and ($null -eq $lastDate -or $hf.InstalledOn -gt $lastDate)) { $lastDate = $hf.InstalledOn }

    if ($null -eq $lastDate) { throw 'Could not determine the last update date.' }

    $age = [math]::Round(((Get-Date) - $lastDate).TotalDays)
    # Updates come monthly, so up to ~35 days is normal.
    $s = Get-LinearScore $age 35 90
    $details = "Last update installed $($lastDate.ToString('yyyy-MM-dd')) ($age days ago)"

    if ($CheckPendingUpdates) {
        try {
            $pending = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'").Updates
            $n = $pending.Count
            $sec = @($pending | Where-Object { $_.MsrcSeverity -in 'Critical', 'Important' }).Count
            $details += "; $n pending ($sec critical/important)"
            $s -= ($sec * 15) + (($n - $sec) * 3)
        }
        catch { $details += '; pending-update search failed' }
    }

    @{
        Score   = $s
        Details = $details
        Advice  = 'Windows is not up to date. Open Settings > Windows Update and install updates.'
    }
}

# 6. Antivirus --------------------------------------------------------------
Invoke-Check -Name 'Antivirus' -Weight 15 -Script {
    $mp = $null
    try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch { }

    if ($mp -and $mp.AMServiceEnabled -and $mp.AntivirusEnabled) {
        $s = 100
        $notes = @('Microsoft Defender active')
        if (-not $mp.RealTimeProtectionEnabled) { $s -= 50; $notes += 'REAL-TIME PROTECTION OFF' }

        $age = $mp.AntivirusSignatureAge
        if ($age -gt 7) { $s -= 40 } elseif ($age -gt 3) { $s -= 15 }
        $notes += "signatures $age day(s) old"

        if ($mp.PSObject.Properties['IsTamperProtected'] -and $mp.IsTamperProtected -eq $false) {
            $s -= 10; $notes += 'tamper protection off'
        }
        if ($mp.QuickScanAge -gt 30 -and $mp.QuickScanAge -lt 4000) {
            $s -= 5; $notes += "last quick scan $($mp.QuickScanAge) days ago"
        }
    }
    else {
        # Third-party antivirus (or Defender off) - ask Windows Security Center
        $products = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct)
        $s = 0
        $notes = @()
        foreach ($p in $products) {
            $hex = '{0:X6}' -f [int]$p.productState
            $enabled = $hex.Substring(2, 2) -in '10', '11'
            $upToDate = $hex.Substring(4, 2) -eq '00'
            $state = if ($enabled) { 'on' } else { 'off' }
            if ($enabled) { if ($upToDate) { $ps = 100 } else { $ps = 50; $state += ', outdated' } } else { $ps = 0 }
            if ($ps -gt $s) { $s = $ps }
            $notes += "$($p.displayName) ($state)"
        }
        if ($notes.Count -eq 0) { $notes = @('No antivirus product registered') }
    }

    $cap = $null
    if ($s -lt 50) { $cap = 50 }
    @{
        Score   = $s
        Details = $notes -join ', '
        Advice  = 'Antivirus protection is missing or weak. Open Windows Security and turn on real-time protection / update definitions.'
        Cap     = $cap
    }
}

# 7. Firewall ---------------------------------------------------------------
Invoke-Check -Name 'Firewall' -Weight 10 -Script {
    $profiles = @(Get-NetFirewallProfile)
    $on = @($profiles | Where-Object { "$($_.Enabled)" -eq 'True' })
    $s = $on.Count / $profiles.Count * 100
    $details = ($profiles | ForEach-Object {
        $st = if ("$($_.Enabled)" -eq 'True') { 'on' } else { 'OFF' }
        "$($_.Name): $st"
    }) -join ', '

    if ($s -lt 100) {
        # A third-party firewall may have replaced the Windows one
        $fw = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName FirewallProduct -ErrorAction SilentlyContinue |
            Where-Object { ('{0:X6}' -f [int]$_.productState).Substring(2, 2) -in '10', '11' })
        if ($fw.Count -gt 0) {
            $s = 100
            $details += "; third-party firewall active: $(($fw | ForEach-Object displayName) -join ', ')"
        }
    }
    @{
        Score   = $s
        Details = $details
        Advice  = 'One or more firewall profiles are off. Turn them on in Windows Security > Firewall & network protection.'
    }
}

# 8. Uptime and pending reboot ---------------------------------------------
Invoke-Check -Name 'Uptime / reboot' -Weight 5 -Script {
    $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    $days = [math]::Round(((Get-Date) - $boot).TotalDays, 1)
    $s = Get-LinearScore $days 7 45

    $reasons = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reasons += 'component servicing' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $reasons += 'Windows Update' }
    $pfro = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
    if ($pfro -and $pfro.PendingFileRenameOperations) { $reasons += 'pending file operations' }

    $details = "Up $days days (since $($boot.ToString('yyyy-MM-dd HH:mm')))"
    if ($reasons.Count -gt 0) {
        $s = [math]::Min($s, 50)
        $details += "; REBOOT PENDING ($($reasons -join ', '))"
    }
    @{
        Score   = $s
        Details = $details
        Advice  = 'Restart the PC (use Restart, not Shut down - Fast Startup does not reset uptime).'
    }
}

# 9. Event logs -------------------------------------------------------------
Invoke-Check -Name 'Event logs' -Weight 10 -Script {
    $day = (Get-Date).AddDays(-1)
    $week = (Get-Date).AddDays(-7)

    $sysEv = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Level = 1, 2; StartTime = $day } -ErrorAction SilentlyContinue)
    $appEv = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Level = 1, 2; StartTime = $day } -ErrorAction SilentlyContinue)
    $crit = @($sysEv + $appEv | Where-Object { $_.Level -eq 1 }).Count
    $sysErr = @($sysEv | Where-Object { $_.Level -eq 2 }).Count
    $appErr = @($appEv | Where-Object { $_.Level -eq 2 }).Count

    # Unexpected shutdowns, blue screens and disk errors over the last 7 days
    $unexpected = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41; StartTime = $week } -ErrorAction SilentlyContinue).Count
    $bsod = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; Id = 1001; StartTime = $week } -ErrorAction SilentlyContinue).Count
    $diskErr = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'disk', 'Ntfs'; Id = 7, 51, 55, 153; StartTime = $week } -ErrorAction SilentlyContinue).Count

    $s = 100
    $s -= $crit * 5
    $s -= [math]::Min($sysErr, 30)
    $s -= [math]::Min($appErr, 20) * 0.5
    $s -= $unexpected * 15
    $s -= $bsod * 20
    $s -= [math]::Min($diskErr * 5, 30)

    @{
        Score   = $s
        Details = "24h: $crit critical, $sysErr system errors, $appErr app errors. 7d: $unexpected unexpected shutdowns, $bsod blue screens, $diskErr disk errors"
        Advice  = 'Errors in the event log. Check Event Viewer (eventvwr.msc) > Windows Logs > System for details.'
    }
}

# 10. Core services ---------------------------------------------------------
Invoke-Check -Name 'Core services' -Weight 5 -Script {
    $names = 'EventLog', 'Winmgmt', 'RpcSs', 'Dhcp', 'Dnscache', 'BFE', 'mpssvc', 'CryptSvc',
             'LanmanWorkstation', 'Schedule', 'ProfSvc', 'SamSs', 'nsi', 'AudioSrv', 'Wcmsvc'
    $bad = @()
    $checked = 0
    foreach ($n in $names) {
        $svc = Get-Service -Name $n -ErrorAction SilentlyContinue
        if (-not $svc) { continue }
        $checked++
        if ($svc.Status -ne 'Running') { $bad += "$n ($($svc.Status), $($svc.StartType))" }
    }
    $details = "$($checked - $bad.Count) of $checked running"
    if ($bad.Count -gt 0) { $details += "; not running: $($bad -join ', ')" }
    @{
        Score   = 100 - 20 * $bad.Count
        Details = $details
        Advice  = 'Important Windows services are stopped. Open services.msc and start them (set to Automatic).'
    }
}

# 11. Security baseline -----------------------------------------------------
Invoke-Check -Name 'Security baseline' -Weight 5 -Script {
    $points = 0
    $max = 0
    $notes = @()

    # UAC
    $max += 40
    $lua = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue).EnableLUA
    if ($lua -eq 1) { $points += 40; $notes += 'UAC on' } else { $notes += 'UAC OFF' }

    # BitLocker on system drive (works without admin via the shell)
    try {
        $shell = New-Object -ComObject Shell.Application
        $bl = $shell.NameSpace($env:SystemDrive).Self.ExtendedProperty('System.Volume.BitLockerProtection')
        if ($null -ne $bl) {
            $max += 15
            if ($bl -in 1, 3, 5) { $points += 15; $notes += 'BitLocker on' } else { $notes += 'BitLocker off' }
        }
    }
    catch { }

    if ($IsAdmin) {
        try {
            $max += 30
            if (Confirm-SecureBootUEFI -ErrorAction Stop) { $points += 30; $notes += 'Secure Boot on' }
            else { $notes += 'Secure Boot off' }
        }
        catch { $max -= 30; $notes += 'Secure Boot n/a (legacy BIOS?)' }

        try {
            $tpm = Get-Tpm -ErrorAction Stop
            $max += 15
            if ($tpm.TpmPresent -and $tpm.TpmReady) { $points += 15; $notes += 'TPM ready' }
            else { $notes += 'TPM not ready' }
        }
        catch { }
    }
    else { $notes += 'Secure Boot/TPM need admin' }

    @{
        Score   = $points / $max * 100
        Details = $notes -join ', '
        Advice  = 'Security features are off. Turn on UAC, Secure Boot (in UEFI) and BitLocker/device encryption where available.'
    }
}

# 12. Battery (laptops only) ------------------------------------------------
Invoke-Check -Name 'Battery' -Weight 5 -Script {
    $bat = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue
    if (-not $bat) { return @{ Score = $null; Details = 'No battery (desktop PC)' } }

    $full = (Get-CimInstance -Namespace root/wmi -ClassName BatteryFullChargedCapacity -ErrorAction Stop |
        Measure-Object FullChargedCapacity -Sum).Sum
    $design = (Get-CimInstance -Namespace root/wmi -ClassName BatteryStaticData -ErrorAction Stop |
        Measure-Object DesignedCapacity -Sum).Sum
    if (-not $design) { throw 'Design capacity not reported.' }

    $health = [math]::Round($full / $design * 100, 1)
    @{
        Score   = Get-LinearScore $health 80 40
        Details = "Battery capacity $health % of design ($full / $design mWh), charge $($bat.EstimatedChargeRemaining) %"
        Advice  = 'Battery has worn down a lot. Consider replacing it. Run "powercfg /batteryreport" for details.'
    }
}

Write-Progress -Activity 'Checking system health' -Completed

# ---------------------------------------------------------------------------
# Overall score
# ---------------------------------------------------------------------------

$scored = @($Results | Where-Object { $null -ne $_.Score })
$weightSum = ($scored | Measure-Object Weight -Sum).Sum
if (-not $weightSum) { throw 'No checks could run.' }
$weighted = ($scored | ForEach-Object { $_.Score * $_.Weight } | Measure-Object -Sum).Sum
$overall = $weighted / $weightSum

$caps = @($Results | Where-Object { $null -ne $_.Cap } | ForEach-Object { $_.Cap })
$capNote = ''
if ($caps.Count -gt 0) {
    $cap = ($caps | Measure-Object -Minimum).Minimum
    if ($overall -gt $cap) { $overall = $cap; $capNote = " (capped at $cap due to a serious problem)" }
}
$overall = [int][math]::Max(1, [math]::Min(100, [math]::Round($overall)))

if ($overall -ge 90) { $rating = 'Excellent'; $color = 'Green' }
elseif ($overall -ge 75) { $rating = 'Good'; $color = 'Green' }
elseif ($overall -ge 60) { $rating = 'Fair'; $color = 'Yellow' }
elseif ($overall -ge 40) { $rating = 'Poor'; $color = 'DarkYellow' }
else { $rating = 'Critical'; $color = 'Red' }

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

$statusColor = @{ OK = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; SKIP = 'DarkGray' }

Write-Host ''
Write-Host '==================================================================' -ForegroundColor Cyan
Write-Host ' SYSTEM HEALTH REPORT' -ForegroundColor Cyan
Write-Host '==================================================================' -ForegroundColor Cyan
Write-Host (" Computer : {0}" -f $env:COMPUTERNAME)
Write-Host (" OS       : {0} (build {1})" -f $os.Caption, $build)
Write-Host (" Date     : {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm'))
$adminText = if ($IsAdmin) { 'yes' } else { 'no (some checks limited)' }
Write-Host (" Admin    : {0}" -f $adminText)
Write-Host '------------------------------------------------------------------' -ForegroundColor Cyan

foreach ($r in $Results) {
    $scoreText = if ($null -eq $r.Score) { '  -  ' } else { '{0,3:N0}' -f $r.Score }
    Write-Host ('[{0,-4}] ' -f $r.Status) -ForegroundColor $statusColor[$r.Status] -NoNewline
    Write-Host ('{0,-18} {1,5}/100  (weight {2,2})' -f $r.Check, $scoreText, $r.Weight)
    Write-Host ('         {0}' -f $r.Details) -ForegroundColor DarkGray
}

$filled = [int][math]::Round($overall / 5)
$bar = ('#' * $filled) + ('-' * (20 - $filled))
Write-Host '------------------------------------------------------------------' -ForegroundColor Cyan
Write-Host ' OVERALL SCORE: ' -NoNewline
Write-Host ("{0}/100  [{1}]  {2}{3}" -f $overall, $bar, $rating, $capNote) -ForegroundColor $color
Write-Host '==================================================================' -ForegroundColor Cyan

$todo = @($Results | Where-Object { $_.Status -in 'WARN', 'FAIL' -and $_.Advice } | Sort-Object Score)
if ($todo.Count -gt 0) {
    Write-Host ''
    Write-Host ' Recommendations:' -ForegroundColor Cyan
    foreach ($t in $todo) {
        Write-Host (" - {0}: {1}" -f $t.Check, $t.Advice) -ForegroundColor $statusColor[$t.Status]
    }
}
Write-Host ''

# ---------------------------------------------------------------------------
# Report / pipeline
# ---------------------------------------------------------------------------

$report = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    OS           = $os.Caption
    Build        = $build
    Timestamp    = (Get-Date).ToString('s')
    IsAdmin      = $IsAdmin
    Score        = $overall
    Rating       = $rating
    Checks       = $Results | Select-Object Check, Weight, Score, Status, Details
}

if ($ReportPath) {
    $ext = [IO.Path]::GetExtension($ReportPath).ToLower()
    switch ($ext) {
        '.json' { $report | ConvertTo-Json -Depth 4 | Set-Content -Path $ReportPath -Encoding UTF8 }
        '.csv' {
            $report.Checks | Select-Object @{ n = 'Computer'; e = { $report.ComputerName } },
                @{ n = 'Timestamp'; e = { $report.Timestamp } },
                @{ n = 'OverallScore'; e = { $report.Score } }, * |
                Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8
        }
        default { Write-Warning "Unsupported report type '$ext'. Use .json or .csv." }
    }
    if ($ext -in '.json', '.csv') { Write-Host " Report saved to $ReportPath" -ForegroundColor Cyan }
}

if ($PassThru) { $report }
