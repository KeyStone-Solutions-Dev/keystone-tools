<#
.SYNOPSIS
Audits built-in domain Administrator account usage across domain controllers.

.DESCRIPTION
Discovers the built-in RID 500 account in the current domain or every reachable domain in the forest,
queries each domain controller for recent security events tied to that account, and checks DC services
and scheduled tasks for direct account dependencies. The script is intended to help validate whether the
built-in domain Administrator account can be disabled safely.

.PARAMETER DaysBack
Number of days of security events to review on each domain controller.

.PARAMETER IncludeForestDomains
Query every domain in the current forest. If omitted, only the current domain is audited.

.PARAMETER AllDomainControllers
Audit every domain controller in scope. If omitted, only the local domain controller is audited.

.PARAMETER OutputPath
Path to the Excel workbook to create. A timestamped .xlsx file is created by default. If ImportExcel is not available, the script falls back to a timestamped folder of CSV files.

.PARAMETER SkipConfigurationChecks
Skip scheduled task and service dependency checks on domain controllers.

.EXAMPLE
.\Get-DefaultDomainAdministratorUsageAudit.ps1

.EXAMPLE
.\Get-DefaultDomainAdministratorUsageAudit.ps1 -DaysBack 180 -IncludeForestDomains

.EXAMPLE
.\Get-DefaultDomainAdministratorUsageAudit.ps1 -AllDomainControllers
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 3650)]
    [int]$DaysBack = 90,

    [switch]$IncludeForestDomains,

    [switch]$AllDomainControllers,

    [string]$OutputPath = (Join-Path -Path (Get-Location) -ChildPath ((Get-Date).ToString("yyyyMMdd_HHmmss") + '_DomainAdministratorUsageAudit.xlsx')),

    [switch]$SkipConfigurationChecks
)

$ErrorActionPreference = 'Stop'

function Assert-ActiveDirectoryModule {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw 'The ActiveDirectory module is required. Run this on a domain controller or a system with RSAT installed.'
    }

    Import-Module ActiveDirectory -ErrorAction Stop
}

function Initialize-ExportMode {
    if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
        return $false
    }

    Import-Module ImportExcel -ErrorAction Stop
    return $true
}

function Get-LocalComputerFqdn {
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($computerSystem.Domain)) {
        return $env:COMPUTERNAME
    }

    return ('{0}.{1}' -f $env:COMPUTERNAME, $computerSystem.Domain)
}

function Export-WorksheetData {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$WorksheetName,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object[]]$Rows
    )

    $worksheetRows = if ($Rows -and $Rows.Count -gt 0) {
        $Rows
    }
    else {
        @([PSCustomObject]@{
            Status = 'No records found'
        })
    }

    $exportParams = @{
        Path          = $Path
        WorksheetName = $WorksheetName
        AutoSize      = $true
        FreezeTopRow  = $true
        BoldTopRow    = $true
    }

    if (Test-Path -Path $Path) {
        $exportParams.Append = $true
    }

    $worksheetRows | Export-Excel @exportParams
}

function Get-EventFieldMap {
    param(
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Eventing.Reader.EventRecord]$Event
    )

    $fields = @{}
    $xml = [xml]$Event.ToXml()

    foreach ($node in $xml.Event.EventData.Data) {
        $name = [string]$node.Name
        if ([string]::IsNullOrWhiteSpace($name)) {
            continue
        }

        $fields[$name] = [string]$node.'#text'
    }

    return $fields
}

function Resolve-EventMatch {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$FieldMap,

        [Parameter(Mandatory = $true)]
        [string]$AdministratorSid,

        [Parameter(Mandatory = $true)]
        [string[]]$AccountNames,

        [Parameter(Mandatory = $true)]
        [string[]]$DomainNames
    )

    $sidFields = @(
        'TargetUserSid',
        'TargetSid',
        'SubjectUserSid',
        'MemberSid',
        'AccountSid'
    )

    foreach ($field in $sidFields) {
        if ($FieldMap.ContainsKey($field) -and $FieldMap[$field] -eq $AdministratorSid) {
            return "SID:$field"
        }
    }

    $nameFields = @(
        'TargetUserName',
        'TargetUser',
        'SubjectUserName',
        'AccountName',
        'MemberName'
    )

    $domainFields = @(
        'TargetDomainName',
        'TargetDomain',
        'SubjectDomainName',
        'AccountDomain'
    )

    foreach ($field in $nameFields) {
        if (-not $FieldMap.ContainsKey($field)) {
            continue
        }

        $candidateName = [string]$FieldMap[$field]
        if ([string]::IsNullOrWhiteSpace($candidateName)) {
            continue
        }

        $nameMatched = $false
        foreach ($accountName in $AccountNames) {
            if ($candidateName.Equals($accountName, [System.StringComparison]::OrdinalIgnoreCase)) {
                $nameMatched = $true
                break
            }
        }

        if (-not $nameMatched) {
            continue
        }

        foreach ($domainField in $domainFields) {
            if (-not $FieldMap.ContainsKey($domainField)) {
                continue
            }

            foreach ($domainName in $DomainNames) {
                if ([string]::IsNullOrWhiteSpace($domainName)) {
                    continue
                }

                if ($FieldMap[$domainField].Equals($domainName, [System.StringComparison]::OrdinalIgnoreCase)) {
                    return "Name:$field/$domainField"
                }
            }
        }

        return "Name:$field"
    }

    return $null
}

function Get-EventLabel {
    param([int]$Id)

    switch ($Id) {
        4624 { 'Successful logon' }
        4625 { 'Failed logon' }
        4648 { 'Explicit credentials used' }
        4672 { 'Special privileges assigned' }
        4723 { 'Password change attempted' }
        4724 { 'Password reset attempted' }
        4740 { 'Account locked out' }
        4768 { 'Kerberos TGT requested' }
        4769 { 'Kerberos service ticket requested' }
        4771 { 'Kerberos pre-auth failed' }
        default { "Event $Id" }
    }
}

function Get-LogonTypeLabel {
    param([string]$LogonType)

    switch ($LogonType) {
        '2' { 'Interactive' }
        '3' { 'Network' }
        '4' { 'Batch' }
        '5' { 'Service' }
        '7' { 'Unlock' }
        '8' { 'NetworkCleartext' }
        '9' { 'NewCredentials' }
        '10' { 'RemoteInteractive' }
        '11' { 'CachedInteractive' }
        default { $LogonType }
    }
}

function Get-DomainAdministratorAccount {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainDnsName
    )

    $domain = Get-ADDomain -Identity $DomainDnsName -Server $DomainDnsName -ErrorAction Stop
    $administratorSid = "$($domain.DomainSID.Value)-500"
    $account = Get-ADUser -Identity $administratorSid -Server $DomainDnsName -Properties Enabled, LastLogonDate, lastLogonTimestamp, PasswordLastSet, PasswordNeverExpires, ServicePrincipalName, adminCount, whenChanged, CanonicalName -ErrorAction Stop

    [PSCustomObject]@{
        DomainDnsName         = $domain.DNSRoot
        NetBIOSName           = $domain.NetBIOSName
        DistinguishedName     = $account.DistinguishedName
        SamAccountName        = $account.SamAccountName
        Name                  = $account.Name
        SID                   = $account.SID.Value
        Enabled               = [bool]$account.Enabled
        LastLogonDate         = $account.LastLogonDate
        LastLogonTimestamp    = if ($account.lastLogonTimestamp) { [DateTime]::FromFileTime([int64]$account.lastLogonTimestamp) } else { $null }
        PasswordLastSet       = $account.PasswordLastSet
        PasswordNeverExpires  = [bool]$account.PasswordNeverExpires
        ServicePrincipalNames = ($account.ServicePrincipalName -join '; ')
        AdminCount            = $account.adminCount
        WhenChanged           = $account.whenChanged
        CanonicalName         = $account.CanonicalName
    }
}

function Get-DomainControllerAuditEvents {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [DateTime]$StartTime,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$AdministratorAccount
    )

    $eventIds = @(4624, 4625, 4648, 4672, 4723, 4724, 4740, 4768, 4769, 4771)
    $events = Get-WinEvent -ComputerName $ComputerName -FilterHashtable @{ LogName = 'Security'; Id = $eventIds; StartTime = $StartTime } -ErrorAction Stop

    $domainNames = @(
        $AdministratorAccount.DomainDnsName,
        $AdministratorAccount.NetBIOSName
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique

    $accountNames = @(
        $AdministratorAccount.SamAccountName,
        $AdministratorAccount.Name
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique

    foreach ($eventRecord in $events) {
        $fieldMap = Get-EventFieldMap -Event $eventRecord
        $matchedOn = Resolve-EventMatch -FieldMap $fieldMap -AdministratorSid $AdministratorAccount.SID -AccountNames $accountNames -DomainNames $domainNames
        if (-not $matchedOn) {
            continue
        }

        [PSCustomObject]@{
            Domain                = $AdministratorAccount.DomainDnsName
            DomainController      = $ComputerName
            TimeCreated           = $eventRecord.TimeCreated
            EventId               = $eventRecord.Id
            EventName             = Get-EventLabel -Id $eventRecord.Id
            MatchedOn             = $matchedOn
            TargetUser            = $fieldMap['TargetUserName']
            TargetDomain          = $fieldMap['TargetDomainName']
            SubjectUser           = $fieldMap['SubjectUserName']
            SubjectDomain         = $fieldMap['SubjectDomainName']
            WorkstationName       = $fieldMap['WorkstationName']
            IpAddress             = $fieldMap['IpAddress']
            IpPort                = $fieldMap['IpPort']
            LogonType             = Get-LogonTypeLabel -LogonType $fieldMap['LogonType']
            AuthenticationPackage = $fieldMap['AuthenticationPackageName']
            ProcessName           = $fieldMap['ProcessName']
            ServiceName           = $fieldMap['ServiceName']
            Status                = $fieldMap['Status']
            SubStatus             = $fieldMap['SubStatus']
        }
    }
}

function Test-AccountReference {
    param(
        [string]$Candidate,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$AdministratorAccount
    )

    if ([string]::IsNullOrWhiteSpace($Candidate)) {
        return $false
    }

    $referenceValues = @(
        $AdministratorAccount.SamAccountName,
        $AdministratorAccount.Name,
        "$($AdministratorAccount.NetBIOSName)\$($AdministratorAccount.SamAccountName)",
        "$($AdministratorAccount.DomainDnsName)\$($AdministratorAccount.SamAccountName)",
        "$($AdministratorAccount.SamAccountName)@$($AdministratorAccount.DomainDnsName)",
        $AdministratorAccount.SID
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    foreach ($reference in $referenceValues) {
        if ($Candidate.Equals($reference, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

function Get-DomainControllerTaskDependencies {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$AdministratorAccount
    )

    $session = New-CimSession -ComputerName $ComputerName -ErrorAction Stop
    try {
        $tasks = Get-ScheduledTask -CimSession $session -ErrorAction Stop | Where-Object {
            Test-AccountReference -Candidate $_.Principal.UserId -AdministratorAccount $AdministratorAccount
        }

        foreach ($task in $tasks) {
            [PSCustomObject]@{
                Domain           = $AdministratorAccount.DomainDnsName
                DomainController = $ComputerName
                TaskName         = $task.TaskName
                TaskPath         = $task.TaskPath
                RunAsUser        = $task.Principal.UserId
                LogonType        = $task.Principal.LogonType
                TaskState        = $task.State
            }
        }
    }
    finally {
        if ($session) {
            $session | Remove-CimSession -ErrorAction SilentlyContinue
        }
    }
}

function Get-DomainControllerServiceDependencies {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$AdministratorAccount
    )

    Get-CimInstance -ClassName Win32_Service -ComputerName $ComputerName -ErrorAction Stop |
        Where-Object { Test-AccountReference -Candidate $_.StartName -AdministratorAccount $AdministratorAccount } |
        ForEach-Object {
            [PSCustomObject]@{
                Domain           = $AdministratorAccount.DomainDnsName
                DomainController = $ComputerName
                ServiceName      = $_.Name
                DisplayName      = $_.DisplayName
                State            = $_.State
                StartMode        = $_.StartMode
                StartName        = $_.StartName
            }
        }
}

Assert-ActiveDirectoryModule

$startTime = (Get-Date).AddDays(-$DaysBack)
$domainsToAudit = if ($IncludeForestDomains) {
    (Get-ADForest -ErrorAction Stop).Domains | Sort-Object -Unique
} else {
    @((Get-ADDomain -ErrorAction Stop).DNSRoot)
}

Write-Verbose ("Discovered {0} domain(s) to audit: {1}" -f $domainsToAudit.Count, ($domainsToAudit -join ', '))
$localComputerName = $env:COMPUTERNAME
$localComputerFqdn = Get-LocalComputerFqdn
$useExcelExport = Initialize-ExportMode

if (-not $useExcelExport) {
    Write-Warning 'ImportExcel is not installed. Falling back to CSV folder export.'
}

$administratorAccounts = [System.Collections.Generic.List[object]]::new()
$domainControllers = [System.Collections.Generic.List[object]]::new()
$securityEvents = [System.Collections.Generic.List[object]]::new()
$taskDependencies = [System.Collections.Generic.List[object]]::new()
$serviceDependencies = [System.Collections.Generic.List[object]]::new()
$failures = [System.Collections.Generic.List[object]]::new()

$domainIndex = 0

foreach ($domainDnsName in $domainsToAudit) {
    $domainIndex++
    Write-Progress -Id 1 -Activity 'Auditing built-in domain administrator usage' -Status "Resolving domain $domainDnsName ($domainIndex of $($domainsToAudit.Count))" -PercentComplete (($domainIndex / [math]::Max($domainsToAudit.Count, 1)) * 100)
    Write-Verbose "[$domainDnsName] Resolving built-in RID 500 administrator account."

    try {
        $administratorAccount = Get-DomainAdministratorAccount -DomainDnsName $domainDnsName
        $administratorAccounts.Add($administratorAccount) | Out-Null
    }
    catch {
        $failures.Add([PSCustomObject]@{
            Scope   = 'Domain'
            Target  = $domainDnsName
            Action  = 'Resolve built-in administrator account'
            Message = $_.Exception.Message
        }) | Out-Null
        continue
    }

    if ($AllDomainControllers) {
        Write-Verbose "[$domainDnsName] Enumerating domain controllers."
        try {
            $dcs = Get-ADDomainController -Filter * -Server $domainDnsName -ErrorAction Stop | Sort-Object HostName
        }
        catch {
            $failures.Add([PSCustomObject]@{
                Scope   = 'Domain'
                Target  = $domainDnsName
                Action  = 'Enumerate domain controllers'
                Message = $_.Exception.Message
            }) | Out-Null
            continue
        }
    }
    else {
        Write-Verbose "[$domainDnsName] Resolving local domain controller only."
        try {
            $dcs = @(Get-ADDomainController -Identity $localComputerFqdn -Server $domainDnsName -ErrorAction Stop)
        }
        catch {
            try {
                $dcs = @(Get-ADDomainController -Identity $localComputerName -Server $domainDnsName -ErrorAction Stop)
            }
            catch {
                $failures.Add([PSCustomObject]@{
                    Scope   = 'Domain'
                    Target  = $domainDnsName
                    Action  = 'Resolve local domain controller'
                    Message = $_.Exception.Message
                }) | Out-Null
                continue
            }
        }
    }

    Write-Verbose ("[{0}] Auditing {1} domain controller(s)." -f $domainDnsName, $dcs.Count)
    $dcIndex = 0

    foreach ($dc in $dcs) {
        $dcIndex++
        $dcStatus = "$($dc.HostName) ($dcIndex of $($dcs.Count))"
        Write-Progress -Id 2 -ParentId 1 -Activity "Auditing domain controllers in $domainDnsName" -Status $dcStatus -PercentComplete (($dcIndex / [math]::Max($dcs.Count, 1)) * 100)
        Write-Verbose "[$($dc.HostName)] Querying Security log."

        $domainControllers.Add([PSCustomObject]@{
            Domain               = $administratorAccount.DomainDnsName
            DomainController     = $dc.HostName
            Site                 = $dc.Site
            IPv4Address          = $dc.IPv4Address
            IsGlobalCatalog      = $dc.IsGlobalCatalog
            OperatingSystem      = $dc.OperatingSystem
            BuiltInAdminEnabled   = $administratorAccount.Enabled
            BuiltInAdminSam       = $administratorAccount.SamAccountName
            BuiltInAdminLastLogon = $administratorAccount.LastLogonDate
        }) | Out-Null

        try {
            foreach ($record in (Get-DomainControllerAuditEvents -ComputerName $dc.HostName -StartTime $startTime -AdministratorAccount $administratorAccount)) {
                $securityEvents.Add($record) | Out-Null
            }
        }
        catch {
            $failures.Add([PSCustomObject]@{
                Scope   = 'DomainController'
                Target  = $dc.HostName
                Action  = 'Query security events'
                Message = $_.Exception.Message
            }) | Out-Null
        }

        if ($SkipConfigurationChecks) {
            continue
        }

        Write-Verbose "[$($dc.HostName)] Querying scheduled tasks."
        try {
            foreach ($record in (Get-DomainControllerTaskDependencies -ComputerName $dc.HostName -AdministratorAccount $administratorAccount)) {
                $taskDependencies.Add($record) | Out-Null
            }
        }
        catch {
            $failures.Add([PSCustomObject]@{
                Scope   = 'DomainController'
                Target  = $dc.HostName
                Action  = 'Query scheduled tasks'
                Message = $_.Exception.Message
            }) | Out-Null
        }

        Write-Verbose "[$($dc.HostName)] Querying services."
        try {
            foreach ($record in (Get-DomainControllerServiceDependencies -ComputerName $dc.HostName -AdministratorAccount $administratorAccount)) {
                $serviceDependencies.Add($record) | Out-Null
            }
        }
        catch {
            $failures.Add([PSCustomObject]@{
                Scope   = 'DomainController'
                Target  = $dc.HostName
                Action  = 'Query services'
                Message = $_.Exception.Message
            }) | Out-Null
        }
    }

    Write-Progress -Id 2 -ParentId 1 -Activity "Auditing domain controllers in $domainDnsName" -Completed
}

Write-Progress -Id 1 -Activity 'Auditing built-in domain administrator usage' -Completed

$summary = foreach ($account in $administratorAccounts) {
    $domainEventCount = @($securityEvents | Where-Object { $_.Domain -eq $account.DomainDnsName }).Count
    $domainTaskCount = @($taskDependencies | Where-Object { $_.Domain -eq $account.DomainDnsName }).Count
    $domainServiceCount = @($serviceDependencies | Where-Object { $_.Domain -eq $account.DomainDnsName }).Count

    [PSCustomObject]@{
        Domain                = $account.DomainDnsName
        SamAccountName        = $account.SamAccountName
        Enabled               = $account.Enabled
        LastLogonDate         = $account.LastLogonDate
        LastLogonTimestamp    = $account.LastLogonTimestamp
        PasswordLastSet       = $account.PasswordLastSet
        PasswordNeverExpires   = $account.PasswordNeverExpires
        SecurityEventCount     = $domainEventCount
        TaskDependencyCount    = $domainTaskCount
        ServiceDependencyCount = $domainServiceCount
    }
}

if (Test-Path -Path $OutputPath) {
    Remove-Item -Path $OutputPath -Force
}

if ($useExcelExport) {
    Export-WorksheetData -Path $OutputPath -WorksheetName 'Summary' -Rows @($summary)
    Export-WorksheetData -Path $OutputPath -WorksheetName 'AdministratorAccounts' -Rows @($administratorAccounts)
    Export-WorksheetData -Path $OutputPath -WorksheetName 'DomainControllers' -Rows @($domainControllers)
    Export-WorksheetData -Path $OutputPath -WorksheetName 'SecurityEvents' -Rows @($securityEvents | Sort-Object TimeCreated)
    Export-WorksheetData -Path $OutputPath -WorksheetName 'TaskDependencies' -Rows @($taskDependencies)
    Export-WorksheetData -Path $OutputPath -WorksheetName 'ServiceDependencies' -Rows @($serviceDependencies)
    Export-WorksheetData -Path $OutputPath -WorksheetName 'Failures' -Rows @($failures)
}
else {
    $csvOutputPath = [System.IO.Path]::Combine(
        [System.IO.Path]::GetDirectoryName($OutputPath),
        [System.IO.Path]::GetFileNameWithoutExtension($OutputPath)
    )

    New-Item -Path $csvOutputPath -ItemType Directory -Force | Out-Null

    $administratorAccounts | Export-Csv -Path (Join-Path $csvOutputPath 'administrator-accounts.csv') -NoTypeInformation -Encoding UTF8
    $domainControllers | Export-Csv -Path (Join-Path $csvOutputPath 'domain-controllers.csv') -NoTypeInformation -Encoding UTF8
    $securityEvents | Sort-Object TimeCreated | Export-Csv -Path (Join-Path $csvOutputPath 'administrator-security-events.csv') -NoTypeInformation -Encoding UTF8
    $taskDependencies | Export-Csv -Path (Join-Path $csvOutputPath 'administrator-task-dependencies.csv') -NoTypeInformation -Encoding UTF8
    $serviceDependencies | Export-Csv -Path (Join-Path $csvOutputPath 'administrator-service-dependencies.csv') -NoTypeInformation -Encoding UTF8
    $failures | Export-Csv -Path (Join-Path $csvOutputPath 'audit-failures.csv') -NoTypeInformation -Encoding UTF8
    $summary | Export-Csv -Path (Join-Path $csvOutputPath 'summary.csv') -NoTypeInformation -Encoding UTF8
    $OutputPath = $csvOutputPath
}

Write-Host ''
Write-Host 'Built-in domain administrator audit summary' -ForegroundColor Cyan
$summary | Format-Table -AutoSize

Write-Host ''
if ($useExcelExport) {
    Write-Host "Output workbook: $OutputPath" -ForegroundColor Green
}
else {
    Write-Host "Output folder: $OutputPath" -ForegroundColor Green
}
Write-Host ("Scope: {0}" -f $(if ($AllDomainControllers) { 'All domain controllers in scope' } else { "Local domain controller only ($localComputerFqdn)" })) -ForegroundColor Green
if ($useExcelExport) {
    Write-Host 'Worksheets:'
    Write-Host '  Summary'
    Write-Host '  AdministratorAccounts'
    Write-Host '  DomainControllers'
    Write-Host '  SecurityEvents'
    Write-Host '  TaskDependencies'
    Write-Host '  ServiceDependencies'
    Write-Host '  Failures'
}
else {
    Write-Host 'Files:'
    Write-Host '  summary.csv'
    Write-Host '  administrator-accounts.csv'
    Write-Host '  domain-controllers.csv'
    Write-Host '  administrator-security-events.csv'
    Write-Host '  administrator-task-dependencies.csv'
    Write-Host '  administrator-service-dependencies.csv'
    Write-Host '  audit-failures.csv'
}

Write-Host ''
Write-Host 'Disablement checklist beyond domain controllers:' -ForegroundColor Yellow
Write-Host '  1. Search member servers and jump boxes for scheduled tasks, services, IIS app pools, SQL Agent jobs, and scripts that may still use the account.'
Write-Host '  2. Review privileged access workflows, break-glass procedures, and password vault entries to confirm the account is not a fallback dependency.'
Write-Host '  3. Confirm the account is not referenced by monitoring tools, backup software, legacy LDAP binds, or third-party appliances.'
Write-Host '  4. If the account has been renamed, validate the RID 500 account specifically; the script tracks the SID-backed built-in account, not just the name.'
