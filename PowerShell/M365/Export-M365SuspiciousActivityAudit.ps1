<#
M365 Mailbox + Sign-in Audit Export (30 days) -> Excel (multi-tab)

Required parameter:
  -UsersCsv "user1@contoso.com,user2@contoso.com"

Optional parameters:
  -DaysBack 30
  -ClientName "ClientName"

Example:
  .\Export-M365SuspiciousActivityAudit.ps1 -UsersCsv "user1@contoso.com,user2@contoso.com" -DaysBack 14 -ClientName "Contoso"

Outputs:
  .\ClientName_Audit_yyyyMMdd_HHmm.xlsx
#>

param(
  [string]$UsersCsv,
  [ValidateRange(1,365)]
  [int]$DaysBack = 30,
  [string]$ClientName = "Audit"
)

# -----------------------------
# CONFIG
# -----------------------------
$Users = if ([string]::IsNullOrWhiteSpace($UsersCsv)) {
  @()
} else {
  $UsersCsv.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ }
}

if (-not $Users -or $Users.Count -eq 0) {
  Write-Host "No users were provided." -ForegroundColor Yellow
  Write-Host "Provide a comma-delimited list with -UsersCsv." -ForegroundColor Yellow
  Write-Host "Optional: -DaysBack <1-365> (default is 30)." -ForegroundColor Yellow
  Write-Host "Example: .\Export-M365SuspiciousActivityAudit.ps1 -UsersCsv `"user1@contoso.com,user2@contoso.com`" -DaysBack 14" -ForegroundColor Yellow
  exit 1
}

$StartUtc = (Get-Date).AddDays(-$DaysBack).ToUniversalTime()
$EndUtc   = (Get-Date).ToUniversalTime()

$Timestamp = (Get-Date).ToString("yyyyMMdd_HHmm")
$OutXlsx   = Join-Path $PWD "${ClientName}_Audit_$Timestamp.xlsx"

# For location filtering - Graph returns countryOrRegion often as "US"
$USCountryCodes = @("US", "USA", "United States", "UnitedStates")

# -----------------------------
# MODULES
# -----------------------------
function Install-RequiredModule {
  param([Parameter(Mandatory)][string]$Name)
  if (-not (Get-Module -ListAvailable -Name $Name)) {
    Write-Host "Installing module $Name (CurrentUser)..." -ForegroundColor Yellow
    Install-Module $Name -Scope CurrentUser -Force
  }
  Import-Module $Name -ErrorAction Stop
}

Install-RequiredModule ImportExcel
Install-RequiredModule ExchangeOnlineManagement
Install-RequiredModule Microsoft.Graph.Authentication

# -----------------------------
# CONNECT
# -----------------------------
Write-Host "Connecting to Exchange Online..." -ForegroundColor Cyan
Connect-ExchangeOnline -ShowProgress:$true | Out-Null

Write-Host "Connecting to Microsoft Graph (Sign-in logs)..." -ForegroundColor Cyan
# Requires admin-consented Graph permissions for sign-in logs in most orgs:
# AuditLog.Read.All (+ Directory.Read.All recommended)
Connect-MgGraph -Scopes @("AuditLog.Read.All","Directory.Read.All") | Out-Null

# -----------------------------
# GRAPH SIGN-IN LOGS (30 days)
# -----------------------------
function Get-SignInsForUsers {
  param(
    [string[]]$UserPrincipalNames,
    [datetime]$StartDateUtc,
    [datetime]$EndDateUtc
  )

  $all = New-Object System.Collections.Generic.List[object]

  foreach ($upn in $UserPrincipalNames) {
    Write-Host "Fetching sign-ins for $upn ..." -ForegroundColor Gray

    # Graph OData datetime format
    $start = $StartDateUtc.ToString("o")
    $end   = $EndDateUtc.ToString("o")

    # NOTE: Use v1.0 auditLogs/signIns endpoint. We page through @odata.nextLink
    # Filter by UPN and date range
    $uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=userPrincipalName eq '$upn' and createdDateTime ge $start and createdDateTime le $end&`$top=999"

    while ($uri) {
      $resp = Invoke-MgGraphRequest -Method GET -Uri $uri
      if ($resp.value) {
        foreach ($row in $resp.value) { $all.Add($row) }
      }
      $uri = $resp.'@odata.nextLink'
    }
  }

  return $all
}

$SignInsRaw = Get-SignInsForUsers -UserPrincipalNames $Users -StartDateUtc $StartUtc -EndDateUtc $EndUtc

# Flatten to Excel-friendly objects
$SignIns = $SignInsRaw | ForEach-Object {
  $country = $_.location.countryOrRegion
  $state   = $_.location.state
  $city    = $_.location.city
  $ip      = $_.ipAddress
  $status  = if ($_.status) { "$($_.status.errorCode) - $($_.status.failureReason)" } else { "" }

  [pscustomobject]@{
    CreatedDateTime      = $_.createdDateTime
    UserPrincipalName    = $_.userPrincipalName
    AppDisplayName       = $_.appDisplayName
    ResourceDisplayName  = $_.resourceDisplayName
    ClientAppUsed        = $_.clientAppUsed
    IPAddress            = $ip
    CountryOrRegion      = $country
    State                = $state
    City                 = $city
    ConditionalAccess    = ($_.appliedConditionalAccessPolicies | ForEach-Object { $_.displayName + ":" + $_.result }) -join "; "
    AuthenticationDetail = ($_.authenticationDetails | ForEach-Object { $_.authenticationMethod + ":" + $_.succeeded }) -join "; "
    DeviceOS             = $_.deviceDetail.operatingSystem
    Browser              = $_.deviceDetail.browser
    DeviceId             = $_.deviceDetail.deviceId
    IsCompliant          = $_.deviceDetail.isCompliant
    IsManaged            = $_.deviceDetail.isManaged
    Status               = $status
    ErrorCode            = $_.status.errorCode
    FailureReason        = $_.status.failureReason
    CorrelationId        = $_.correlationId
    SignInEventTypes     = ($_.signInEventTypes -join ",")
  }
}

$SignInsOutsideUS = $SignIns | Where-Object {
  $c = $_.CountryOrRegion
  $c -and ($USCountryCodes -notcontains $c)
}

$SignInsFailures = $SignIns | Where-Object { $_.ErrorCode -ne 0 }

# -----------------------------
# EXCHANGE: FORWARDING / INBOX RULES / PERMISSIONS
# -----------------------------
Write-Host "Collecting Exchange mailbox settings..." -ForegroundColor Cyan

$MailboxForwarding = foreach ($m in $Users) {
  $mbx = Get-Mailbox -Identity $m -ErrorAction SilentlyContinue
  if ($mbx) {
    [pscustomobject]@{
      Mailbox                    = $m
      ForwardingAddress          = $mbx.ForwardingAddress
      ForwardingSmtpAddress      = $mbx.ForwardingSmtpAddress
      DeliverToMailboxAndForward = $mbx.DeliverToMailboxAndForward
      RecipientTypeDetails       = $mbx.RecipientTypeDetails
    }
  }
}

$MailboxInboxRules = foreach ($m in $Users) {
  Get-InboxRule -Mailbox $m -ErrorAction SilentlyContinue | ForEach-Object {
    [pscustomobject]@{
      MailboxOwnerId         = $m
      RuleName               = $_.Name
      Enabled                = $_.Enabled
      Priority               = $_.Priority
      Description            = $_.Description
      ForwardTo              = ($_.ForwardTo -join "; ")
      RedirectTo             = ($_.RedirectTo -join "; ")
      ForwardAsAttachmentTo  = ($_.ForwardAsAttachmentTo -join "; ")
      DeleteMessage          = $_.DeleteMessage
      MoveToFolder           = $_.MoveToFolder
      MarkAsRead             = $_.MarkAsRead
      StopProcessingRules    = $_.StopProcessingRules
      From                   = ($_.From -join "; ")
      SubjectContainsWords   = ($_.SubjectContainsWords -join "; ")
      BodyContainsWords      = ($_.BodyContainsWords -join "; ")
      SentTo                 = ($_.SentTo -join "; ")
    }
  }
}

$MailboxPermissions = foreach ($m in $Users) {
  # FullAccess delegates
  $full = Get-MailboxPermission -Identity $m -ErrorAction SilentlyContinue |
    Where-Object { $_.User -notlike "NT AUTHORITY\SELF" -and $_.IsInherited -eq $false }

  foreach ($p in $full) {
    [pscustomobject]@{
      Mailbox        = $m
      PermissionType = "MailboxPermission"
      Trustee        = $p.User.ToString()
      AccessRights   = ($p.AccessRights -join ",")
      Deny           = $p.Deny
      Inherited      = $p.IsInherited
    }
  }

  # SendAs / SendOnBehalf (SendAs is recipient permission; SendOnBehalf is on mailbox)
  $sendAs = Get-RecipientPermission -Identity $m -ErrorAction SilentlyContinue
  foreach ($rp in $sendAs) {
    [pscustomobject]@{
      Mailbox        = $m
      PermissionType = "RecipientPermission"
      Trustee        = $rp.Trustee.ToString()
      AccessRights   = ($rp.AccessRights -join ",")
      Deny           = $null
      Inherited      = $null
    }
  }

  $mbx = Get-Mailbox -Identity $m -ErrorAction SilentlyContinue
  if ($mbx -and $mbx.GrantSendOnBehalfTo) {
    foreach ($g in $mbx.GrantSendOnBehalfTo) {
      [pscustomobject]@{
        Mailbox        = $m
        PermissionType = "SendOnBehalf"
        Trustee        = $g.ToString()
        AccessRights   = "SendOnBehalf"
        Deny           = $null
        Inherited      = $null
      }
    }
  }
}

# -----------------------------
# PURVIEW: UNIFIED AUDIT LOG (30 days)
# -----------------------------
Write-Host "Searching Unified Audit Log ($DaysBack days)..." -ForegroundColor Cyan
# Depending on tenant size, you may need to page via SessionId/SessionCommand
$AuditRows = New-Object System.Collections.Generic.List[object]
$SessionId = "${ClientName}_$Timestamp"
$ResultSize = 5000

$batchCount = $ResultSize
while ($batchCount -ge $ResultSize) {
  $batch = Search-UnifiedAuditLog -StartDate $StartUtc -EndDate $EndUtc `
    -UserIds $Users -ResultSize $ResultSize `
    -SessionId $SessionId -SessionCommand "ReturnLargeSet" -ErrorAction Stop

  $batchCount = @($batch).Count

  if ($batchCount -gt 0) {
    foreach ($b in $batch) { $AuditRows.Add($b) }
  }
}

if ($AuditRows.Count -eq 0) {
  Write-Host "Unified Audit Log returned no rows for the provided users/date range." -ForegroundColor Yellow
  Write-Host "Check that auditing is enabled and your account has permission to search audit logs." -ForegroundColor Yellow
}

$UnifiedAuditLog = if ($AuditRows.Count -eq 0) {
  @([pscustomobject]@{
    CreationDate = $null
    UserIds      = $null
    Operation    = $null
    Workload     = $null
    ClientIP     = $null
    ObjectId     = $null
    RecordType   = $null
    ResultStatus = $null
    AuditData    = "No unified audit log records returned for selected users/date range."
  })
} else {
  $AuditRows | ForEach-Object {
    [pscustomobject]@{
      CreationDate = $_.CreationDate
      UserIds      = if ($_.UserIds -is [array]) { $_.UserIds -join "; " } else { [string]$_.UserIds }
      Operation    = $_.Operation
      Workload     = $_.Workload
      ClientIP     = $_.ClientIP
      ObjectId     = $_.ObjectId
      RecordType   = $_.RecordType
      ResultStatus = $_.ResultStatus
      AuditData    = $_.AuditData
    }
  }
}

# -----------------------------
# MESSAGE TRACE (last ~10 days via PS)
# -----------------------------
Write-Host "Collecting Message Trace (last 10 days only via Get-MessageTrace)..." -ForegroundColor Cyan
$TraceStart = (Get-Date).AddDays(-10)
$TraceEnd   = Get-Date

$MessageTrace10 = foreach ($m in $Users) {
  # Search outbound messages sent by the mailbox
  Get-MessageTrace -SenderAddress $m -StartDate $TraceStart -EndDate $TraceEnd -PageSize 5000 -ErrorAction SilentlyContinue |
    Select-Object @{n="SenderAddress";e={$_.SenderAddress}},
                  @{n="RecipientAddress";e={$_.RecipientAddress}},
                  @{n="Subject";e={$_.Subject}},
                  @{n="Status";e={$_.Status}},
                  @{n="FromIP";e={$_.FromIP}},
                  @{n="ToIP";e={$_.ToIP}},
                  @{n="Size";e={$_.Size}},
                  @{n="MessageId";e={$_.MessageId}},
                  @{n="Received";e={$_.Received}}
}

# -----------------------------
# EXPORT TO EXCEL (multi-tab)
# -----------------------------
Write-Host "Writing Excel workbook: $OutXlsx" -ForegroundColor Green

# Clear any existing file
if (Test-Path $OutXlsx) { Remove-Item $OutXlsx -Force }

$SignIns          | Export-Excel -Path $OutXlsx -WorksheetName "SignIns_All"        -AutoSize -FreezeTopRow -BoldTopRow
$SignInsOutsideUS | Export-Excel -Path $OutXlsx -WorksheetName "SignIns_OutsideUS"  -AutoSize -FreezeTopRow -BoldTopRow
$SignInsFailures  | Export-Excel -Path $OutXlsx -WorksheetName "SignIns_Failures"   -AutoSize -FreezeTopRow -BoldTopRow

$MailboxForwarding | Export-Excel -Path $OutXlsx -WorksheetName "Mailbox_Forwarding" -AutoSize -FreezeTopRow -BoldTopRow
$MailboxInboxRules | Export-Excel -Path $OutXlsx -WorksheetName "Mailbox_InboxRules" -AutoSize -FreezeTopRow -BoldTopRow
$MailboxPermissions| Export-Excel -Path $OutXlsx -WorksheetName "Mailbox_Permissions" -AutoSize -FreezeTopRow -BoldTopRow

$UnifiedAuditLog   | Export-Excel -Path $OutXlsx -WorksheetName "UnifiedAuditLog"    -AutoSize -FreezeTopRow -BoldTopRow
$MessageTrace10    | Export-Excel -Path $OutXlsx -WorksheetName "MessageTrace_10Days" -AutoSize -FreezeTopRow -BoldTopRow

Write-Host "Done. Workbook created: $OutXlsx" -ForegroundColor Green

# -----------------------------
# CLEANUP
# -----------------------------
Disconnect-ExchangeOnline -Confirm:$false | Out-Null
Disconnect-MgGraph | Out-Null
