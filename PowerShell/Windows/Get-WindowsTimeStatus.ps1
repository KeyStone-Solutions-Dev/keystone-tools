
# === Windows Time Sync (Minimal) — single-block output with LastRunTime ===

# Configurable staleness threshold (days)
$staleDays = 7

# Collect registry/service info
$w32 = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -ErrorAction SilentlyContinue
$svc = Get-Service W32Time -ErrorAction SilentlyContinue

# Determine NTP usage and server
$usesNtp      = ($w32.Type -eq 'NTP')
$ntpServer    = if ($usesNtp) { $w32.NtpServer } else { '' }

# Service status & start type
$svcStatus    = if ($svc) { $svc.Status } else { 'Not Found' }
$svcStartType = if ($svc) { $svc.StartType } else { 'Not Found' }

# Scheduled tasks under the standard path
$taskPath       = '\Microsoft\Windows\Time Synchronization\'
$neededNames    = @('SynchronizeTime','ForceSynchronizeTime')
$allTasks       = Get-ScheduledTask -TaskPath $taskPath -ErrorAction SilentlyContinue
$existingNeeded = @()
if ($allTasks) { $existingNeeded = $allTasks | Where-Object { $_.TaskName -in $neededNames } }
$tasksPresent   = ($existingNeeded.Count -eq $neededNames.Count)

# Gather LastRunTime across needed tasks (if present)
$lastRunTimes = @()
foreach ($t in $existingNeeded) {
    $ti = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction SilentlyContinue
    if ($ti -and $ti.LastRunTime -and ($ti.LastRunTime -ne [datetime]::MinValue)) {
        $lastRunTimes += $ti.LastRunTime
    }
}

# Compute latest LastRunTime and staleness
$latestLastRun   = if ($lastRunTimes.Count -gt 0) { ($lastRunTimes | Sort-Object -Descending | Select-Object -First 1) } else { $null }
$staleCutoff     = (Get-Date).AddDays(-$staleDays)
$lastRunStatus   = if ($latestLastRun) {
    if ($latestLastRun -lt $staleCutoff) { "Stale (older than $staleDays days)" } else { "OK (within $staleDays days)" }
} else { "Unknown (no LastRunTime available)" }

# Precompute display strings
$syncTypeText   = if ($w32 -and $w32.Type) { $w32.Type } else { '(n/a)' }
$usesNtpText    = if ($usesNtp) { 'Yes' } else { "No (Type: $syncTypeText)" }
$ntpServerText  = if ($usesNtp -and $ntpServer) { $ntpServer } else { '(n/a)' }
$tasksText      = if ($tasksPresent) { 'Present (SynchronizeTime, ForceSynchronizeTime)' } else { 'Missing or not found' }
$lastRunText    = if ($latestLastRun) { $latestLastRun.ToString('yyyy-MM-dd HH:mm:ss') } else { '(n/a)' }

# Emit single, concise block
$lines = @()
$lines += "=== Windows Time Sync (Minimal) ==="
$lines += "Uses NTP         : $usesNtpText"
$lines += "NTP Server       : $ntpServerText"
$lines += "Service StartType: $svcStartType"
$lines += "Service Status   : $svcStatus"
$lines += "Scheduled Tasks  : $tasksText"
$lines += "LastRunTime      : $lastRunText"
$lines += "LastRun Status   : $lastRunStatus"
$lines += "=== End ==="

$lines -join "`n"
