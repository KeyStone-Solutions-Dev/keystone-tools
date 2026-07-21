#Requires -RunAsAdministrator

# Prompt for Username and Date Range
$UserName = Read-Host "Enter the target username"
$StartDate = Read-Host "Enter the start date (yyyy-MM-dd)"
$EndDate = Read-Host "Enter the end date (yyyy-MM-dd)"

# Validate date input
try {
    $StartDate = [datetime]::ParseExact($StartDate, "yyyy-MM-dd", $null)
    $EndDate = [datetime]::ParseExact($EndDate, "yyyy-MM-dd", $null)
} catch {
    Write-Host "Invalid date format. Please use yyyy-MM-dd." -ForegroundColor Red
    return
}

# Event IDs for Logon and Logoff
$LogonEventIDs = @(4624, 4634)

# Retrieve and Process Events
Write-Host "Retrieving Security log events. This may take some time..." -ForegroundColor Yellow
$Events = Get-WinEvent -LogName "Security" | Where-Object {
    ($_.TimeCreated -ge $StartDate) -and ($_.TimeCreated -le $EndDate) -and
    ($LogonEventIDs -contains $_.Id) -and ($_.Properties[5].Value -eq $UserName)
}

if ($Events.Count -eq 0) {
    Write-Host "No relevant events found for user: $UserName." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    return
}

Write-Host "Processing filtered events..." -ForegroundColor Yellow
$UserActivity = $Events | ForEach-Object {
    $EventType = if ($_.Id -eq 4624) { "Logon" } elseif ($_.Id -eq 4634) { "Logoff" } else { "Unknown" }
    $LogonDetails = $_.Properties[10].Value  # Logon Type or details if available
    $SourceIP = $_.Properties[18].Value      # Source IP address if applicable
    
    [PSCustomObject]@{
        Date        = ($_.TimeCreated).ToString("yyyy-MM-dd")
        Time        = ($_.TimeCreated).ToString("HH:mm:ss")
        Username    = $UserName
        EventType   = $EventType
        SourceIP    = if ($SourceIP) { $SourceIP } else { "N/A" }
        LogonDetails = if ($LogonDetails) { $LogonDetails } else { "N/A" }
        EventMessage = $_.Message -replace "`r`n", " "  # Clean multi-line messages
    }
}

# Export Results to CSV
$ReadableOutputPath = "UserActivity_$($UserName)_$($StartDate.ToString('yyyyMMdd'))_to_$($EndDate.ToString('yyyyMMdd')).csv"
$UserActivity | Export-Csv -Path $ReadableOutputPath -NoTypeInformation -Encoding UTF8

Write-Host "User activity successfully exported to $ReadableOutputPath." -ForegroundColor Green
Read-Host "Press Enter to exit"
