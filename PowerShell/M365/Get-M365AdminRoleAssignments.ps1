<#
.SYNOPSIS
    Report every Microsoft 365 / Entra ID admin (directory) role that has assignments,
    listing the users assigned to each role.

.DESCRIPTION
    Enumerates directory role assignments via Microsoft Graph, groups them by role, and
    writes a single console report showing each admin role and the users that hold it.
    Roles with no assignments are omitted. Group- and service-principal-based assignments
    are labelled by principal type so they are visible but distinguishable from users.
    Each user and service principal is reported with its account status (Enabled/Disabled);
    disabled accounts are highlighted in red. Groups show N/A.

    Active (permanent) assignments are always included. Use -IncludeEligible to also
    include PIM eligible assignments (requires Entra ID P2 / Privileged Identity Management).

    Read-only: the script never modifies role assignments. Use -CsvPath to also export the
    flattened results to CSV for audit evidence.

.PARAMETER IncludeEligible
    Also include PIM eligible role assignments in addition to active assignments.

.PARAMETER CsvPath
    Optional path to export the flattened report to CSV.

.PARAMETER SkipGridView
    Suppress the Out-GridView window; console output is always produced.

.NOTES
    Required modules : Microsoft.Graph (Authentication, Identity.Governance)
    Required scopes  : RoleManagement.Read.Directory, User.Read.All, Directory.Read.All
    Permission       : An account able to read directory role assignments (e.g. Global Reader).
#>
[CmdletBinding()]
param(
    [Parameter()]
    [switch]$IncludeEligible,

    [Parameter()]
    [string]$CsvPath,

    [Parameter()]
    [switch]$SkipGridView
)

$requiredCommands = @(
    "Connect-MgGraph",
    "Invoke-MgGraphRequest",
    "Get-MgRoleManagementDirectoryRoleAssignment",
    "Get-MgRoleManagementDirectoryRoleDefinition"
)

if ($IncludeEligible) {
    $requiredCommands += "Get-MgRoleManagementDirectoryRoleEligibilitySchedule"
}

foreach ($command in $requiredCommands) {
    if (-not (Get-Command -Name $command -ErrorAction SilentlyContinue)) {
        throw "Required command not found: $command. Install/load the Microsoft.Graph modules (Microsoft.Graph.Authentication, Microsoft.Graph.Identity.Governance)."
    }
}

function Resolve-PrincipalInfo {
    param(
        [Parameter(Mandatory)]
        $Principal
    )

    # $Principal comes from -ExpandProperty Principal; concrete properties may live on the
    # object or in AdditionalProperties depending on the resolved @odata.type.
    $props = @{}
    if ($Principal.AdditionalProperties) {
        $props = $Principal.AdditionalProperties
    }

    $odataType = $props['@odata.type']
    $principalType = switch ($odataType) {
        '#microsoft.graph.user'             { 'User' }
        '#microsoft.graph.group'            { 'Group' }
        '#microsoft.graph.servicePrincipal' { 'ServicePrincipal' }
        default                             { if ($odataType) { $odataType -replace '#microsoft.graph\.', '' } else { 'Unknown' } }
    }

    $displayName = if ($props['displayName']) { $props['displayName'] } elseif ($Principal.DisplayName) { $Principal.DisplayName } else { '' }
    $upn = if ($props['userPrincipalName']) { $props['userPrincipalName'] } else { '' }

    [PSCustomObject]@{
        Id            = $Principal.Id
        PrincipalType = $principalType
        DisplayName   = $displayName
        UserPrincipalName = $upn
    }
}

# accountEnabled is not returned on the expanded principal, so look it up once per principal.
$accountStatusCache = @{}

function Get-PrincipalAccountStatus {
    param(
        [Parameter(Mandatory)]
        $PrincipalInfo
    )

    $resource = switch ($PrincipalInfo.PrincipalType) {
        'User'             { 'users' }
        'ServicePrincipal' { 'servicePrincipals' }
        default            { return 'N/A' }
    }

    if ($accountStatusCache.ContainsKey($PrincipalInfo.Id)) {
        return $accountStatusCache[$PrincipalInfo.Id]
    }

    try {
        $result = Invoke-MgGraphRequest -Method GET -Uri "v1.0/$resource/$($PrincipalInfo.Id)?`$select=accountEnabled" -ErrorAction Stop
        $status = if ($result['accountEnabled']) { 'Enabled' } else { 'Disabled' }
    }
    catch {
        Write-Warning "Unable to read account status for $($PrincipalInfo.DisplayName) ($($PrincipalInfo.Id))."
        $status = 'Unknown'
    }

    $accountStatusCache[$PrincipalInfo.Id] = $status
    $status
}

Connect-MgGraph -Scopes @(
    "RoleManagement.Read.Directory",
    "User.Read.All",
    "Directory.Read.All"
) -NoWelcome

try {
    Write-Host "Collecting directory role definitions..."
    $roleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All -Property Id,DisplayName
    $roleNameById = @{}
    foreach ($roleDefinition in $roleDefinitions) {
        if ($roleDefinition.Id) {
            $roleNameById[$roleDefinition.Id] = $roleDefinition.DisplayName
        }
    }

    $report = [System.Collections.Generic.List[Object]]::new()

    Write-Host "Collecting active role assignments..."
    $activeAssignments = Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty Principal
    foreach ($assignment in $activeAssignments) {
        if (-not $assignment.RoleDefinitionId -or -not $assignment.Principal) { continue }

        $principal = Resolve-PrincipalInfo -Principal $assignment.Principal
        $roleName = $roleNameById[$assignment.RoleDefinitionId]
        if (-not $roleName) { $roleName = $assignment.RoleDefinitionId }

        $report.Add([PSCustomObject]@{
            Role              = $roleName
            AssignmentType    = "Active"
            PrincipalType     = $principal.PrincipalType
            DisplayName       = $principal.DisplayName
            UserPrincipalName = $principal.UserPrincipalName
            AccountStatus     = Get-PrincipalAccountStatus -PrincipalInfo $principal
        })
    }

    if ($IncludeEligible) {
        Write-Host "Collecting PIM eligible role assignments..."
        try {
            $eligibleAssignments = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All -ExpandProperty Principal
            foreach ($assignment in $eligibleAssignments) {
                if (-not $assignment.RoleDefinitionId -or -not $assignment.Principal) { continue }

                $principal = Resolve-PrincipalInfo -Principal $assignment.Principal
                $roleName = $roleNameById[$assignment.RoleDefinitionId]
                if (-not $roleName) { $roleName = $assignment.RoleDefinitionId }

                $report.Add([PSCustomObject]@{
                    Role              = $roleName
                    AssignmentType    = "Eligible (PIM)"
                    PrincipalType     = $principal.PrincipalType
                    DisplayName       = $principal.DisplayName
                    UserPrincipalName = $principal.UserPrincipalName
                    AccountStatus     = Get-PrincipalAccountStatus -PrincipalInfo $principal
                })
            }
        }
        catch {
            Write-Warning "Unable to collect PIM eligible assignments (Entra ID P2 / PIM may not be enabled). Continuing with active assignments only."
        }
    }

    if ($report.Count -eq 0) {
        Write-Host "No directory role assignments were found."
        return
    }

    # --- Console report, grouped by role ---
    $sortedRoles = $report.Role | Sort-Object -Unique

    Write-Host ""
    Write-Host "Microsoft 365 / Entra ID Admin Role Assignments" -ForegroundColor Cyan
    Write-Host ("Roles with assignments: {0}   Total assignments: {1}" -f $sortedRoles.Count, $report.Count) -ForegroundColor Cyan
    Write-Host ("=" * 70)

    foreach ($roleName in $sortedRoles) {
        $roleMembers = $report | Where-Object { $_.Role -eq $roleName } | Sort-Object PrincipalType, DisplayName
        $userCount = ($roleMembers | Where-Object { $_.PrincipalType -eq 'User' }).Count

        Write-Host ""
        Write-Host ("{0}  ({1} user(s), {2} total assignment(s))" -f $roleName, $userCount, $roleMembers.Count) -ForegroundColor Yellow

        foreach ($member in $roleMembers) {
            $identity = if ($member.UserPrincipalName) { $member.UserPrincipalName } else { $member.DisplayName }
            $statusColor = if ($member.AccountStatus -eq 'Disabled') { 'Red' } else { 'Gray' }
            Write-Host ("    - [{0}] {1}  {2}  [{3}]" -f $member.PrincipalType, $member.DisplayName, $identity, $member.AccountStatus) -ForegroundColor $statusColor
        }
    }

    Write-Host ""
    Write-Host ("=" * 70)

    if ($CsvPath) {
        $report |
            Sort-Object Role, PrincipalType, DisplayName |
            Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Report exported to: $CsvPath"
    }

    if (-not $SkipGridView) {
        $report |
            Sort-Object Role, PrincipalType, DisplayName |
            Out-GridView -Title "M365 Admin Role Assignments"
    }
}
finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue
}
