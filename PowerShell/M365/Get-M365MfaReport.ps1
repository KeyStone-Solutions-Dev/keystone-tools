[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 90)]
    [int]$SignInLookbackDays = 30,

    [Parameter()]
    [switch]$SkipGridView
)

function Test-UserInConditionalAccessPolicy {
    param(
        [Parameter(Mandatory)]
        $Policy,

        [Parameter(Mandatory)]
        [string]$UserId,

        [Parameter(Mandatory)]
        [hashtable]$GroupMembersById,

        [Parameter(Mandatory)]
        [hashtable]$RoleTemplatesByUserId
    )

    $userConditions = $Policy.Conditions.Users
    if (-not $userConditions) { return $false }

    $includeUsers = @($userConditions.IncludeUsers)
    $includeGroups = @($userConditions.IncludeGroups)
    $includeRoles = @($userConditions.IncludeRoles)

    $excludeUsers = @($userConditions.ExcludeUsers)
    $excludeGroups = @($userConditions.ExcludeGroups)
    $excludeRoles = @($userConditions.ExcludeRoles)

    $included = $false

    if ($includeUsers -contains "All" -or $includeUsers -contains $UserId) {
        $included = $true
    }

    if (-not $included -and $includeGroups.Count -gt 0) {
        foreach ($groupId in $includeGroups) {
            if ($groupId -and $GroupMembersById.ContainsKey($groupId) -and $GroupMembersById[$groupId].Contains($UserId)) {
                $included = $true
                break
            }
        }
    }

    if (-not $included -and $includeRoles.Count -gt 0) {
        if ($RoleTemplatesByUserId.ContainsKey($UserId)) {
            $userRoles = $RoleTemplatesByUserId[$UserId]
            foreach ($roleId in $includeRoles) {
                if ($userRoles.Contains($roleId)) {
                    $included = $true
                    break
                }
            }
        }
    }

    if (-not $included) { return $false }

    if ($excludeUsers -contains "All" -or $excludeUsers -contains $UserId) {
        return $false
    }

    foreach ($groupId in $excludeGroups) {
        if ($groupId -and $GroupMembersById.ContainsKey($groupId) -and $GroupMembersById[$groupId].Contains($UserId)) {
            return $false
        }
    }

    if ($excludeRoles.Count -gt 0 -and $RoleTemplatesByUserId.ContainsKey($UserId)) {
        $userRoles = $RoleTemplatesByUserId[$UserId]
        foreach ($roleId in $excludeRoles) {
            if ($userRoles.Contains($roleId)) {
                return $false
            }
        }
    }

    return $true
}

$requiredCommands = @(
    "Connect-MgGraph",
    "Get-MgUser",
    "Get-MgIdentityConditionalAccessPolicy",
    "Get-MgAuditLogSignIn",
    "Get-MgGroupTransitiveMember",
    "Get-MgRoleManagementDirectoryRoleAssignment",
    "Get-MgRoleManagementDirectoryRoleDefinition",
    "Connect-ExchangeOnline",
    "Get-Mailbox"
)

foreach ($command in $requiredCommands) {
    if (-not (Get-Command -Name $command -ErrorAction SilentlyContinue)) {
        throw "Required command not found: $command. Install/load required Microsoft Graph and Exchange Online modules."
    }
}

Connect-MgGraph -Scopes @(
    "AuditLog.Read.All",
    "Policy.Read.All",
    "User.Read.All",
    "Group.Read.All",
    "RoleManagement.Read.Directory"
) -NoWelcome

Connect-ExchangeOnline -ShowBanner:$false

try {
    Write-Host "Collecting Entra ID users (excluding guests)..."
    $users = Get-MgUser -All -Filter "userType ne 'Guest'" -Property Id,DisplayName,UserPrincipalName,AccountEnabled,AssignedLicenses

    Write-Host "Collecting Exchange mailbox data..."
    $mailboxes = Get-Mailbox -RecipientTypeDetails UserMailbox,SharedMailbox -ResultSize Unlimited
    $mailboxByUpn = @{}
    foreach ($mailbox in $mailboxes) {
        if ($mailbox.UserPrincipalName) {
            $mailboxByUpn[$mailbox.UserPrincipalName.ToLowerInvariant()] = $mailbox
        }
    }

    Write-Host "Collecting Conditional Access MFA policies..."
    $policies = Get-MgIdentityConditionalAccessPolicy -All
    $mfaPolicies = $policies | Where-Object {
        $_.State -eq "enabled" -and
        $_.GrantControls -and
        ($_.GrantControls.BuiltInControls -contains "mfa")
    }

    $policyGroupIds =
        $mfaPolicies |
        ForEach-Object { @($_.Conditions.Users.IncludeGroups) + @($_.Conditions.Users.ExcludeGroups) } |
        Where-Object { $_ -and $_ -ne "All" -and $_ -ne "None" } |
        Sort-Object -Unique

    $groupMembersById = @{}
    foreach ($groupId in $policyGroupIds) {
        $memberSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        try {
            $groupMembers = Get-MgGroupTransitiveMember -GroupId $groupId -All -Property Id
            foreach ($member in $groupMembers) {
                $typeName = $member.AdditionalProperties['@odata.type']
                if ($typeName -eq '#microsoft.graph.user' -and $member.Id) {
                    $null = $memberSet.Add($member.Id)
                }
            }
        }
        catch {
            Write-Warning "Unable to enumerate members for group $groupId. Group-based CA matching may be incomplete."
        }
        $groupMembersById[$groupId] = $memberSet
    }

    Write-Host "Collecting role assignments used by Conditional Access..."
    $roleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All -Property Id,TemplateId
    $templateIdByRoleDefinitionId = @{}
    foreach ($roleDefinition in $roleDefinitions) {
        if ($roleDefinition.Id -and $roleDefinition.TemplateId) {
            $templateIdByRoleDefinitionId[$roleDefinition.Id] = $roleDefinition.TemplateId
        }
    }

    $userIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($user in $users) {
        if ($user.Id) {
            $null = $userIds.Add($user.Id)
        }
    }

    $roleTemplatesByUserId = @{}
    $roleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -All -Property PrincipalId,RoleDefinitionId
    foreach ($assignment in $roleAssignments) {
        if (-not $assignment.PrincipalId -or -not $assignment.RoleDefinitionId) { continue }
        if (-not $userIds.Contains($assignment.PrincipalId)) { continue }

        $templateId = $templateIdByRoleDefinitionId[$assignment.RoleDefinitionId]
        if (-not $templateId) {
            $templateId = $assignment.RoleDefinitionId
        }

        if (-not $roleTemplatesByUserId.ContainsKey($assignment.PrincipalId)) {
            $roleTemplatesByUserId[$assignment.PrincipalId] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        }

        $null = $roleTemplatesByUserId[$assignment.PrincipalId].Add($templateId)
    }

    Write-Host "Collecting recent sign-ins for MFA evidence ($SignInLookbackDays days)..."
    $lookbackUtc = (Get-Date).ToUniversalTime().AddDays(-$SignInLookbackDays)
    $signInFilter = "createdDateTime ge $($lookbackUtc.ToString("o"))"
    $signIns = Get-MgAuditLogSignIn -All -Filter $signInFilter -Property UserId,AuthenticationRequirement,CreatedDateTime

    $mfaSeenByUserId = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($signIn in $signIns) {
        if ($signIn.UserId -and $signIn.AuthenticationRequirement -eq "multiFactorAuthentication") {
            $null = $mfaSeenByUserId.Add($signIn.UserId)
        }
    }

    Write-Host "Building report for $($users.Count) users..."
    $report = [System.Collections.Generic.List[Object]]::new()

    foreach ($user in $users) {
        $upn = $user.UserPrincipalName
        if (-not $upn) { continue }

        $mailbox = $null
        $lookupUpn = $upn.ToLowerInvariant()
        if ($mailboxByUpn.ContainsKey($lookupUpn)) {
            $mailbox = $mailboxByUpn[$lookupUpn]
        }

        $matchingPolicies = @()
        foreach ($policy in $mfaPolicies) {
            if (Test-UserInConditionalAccessPolicy -Policy $policy -UserId $user.Id -GroupMembersById $groupMembersById -RoleTemplatesByUserId $roleTemplatesByUserId) {
                $matchingPolicies += $policy
            }
        }

        $isTargetedByCaMfa = $matchingPolicies.Count -gt 0
        $hasRecentMfaRequirement = $mfaSeenByUserId.Contains($user.Id)

        $mfaStatus = if ($hasRecentMfaRequirement) {
            "Enforced (Recent Sign-In)"
        }
        elseif ($isTargetedByCaMfa) {
            "Targeted by Conditional Access"
        }
        else {
            "No MFA Requirement Observed"
        }

        $report.Add([PSCustomObject]@{
            User                = $upn
            Name                = $user.DisplayName
            MFAStatus           = $mfaStatus
            CATargeted          = $isTargetedByCaMfa
            RecentMFARequired   = $hasRecentMfaRequirement
            CAPolicies          = ($matchingPolicies.DisplayName | Sort-Object -Unique) -join ';'
            MailboxType         = if ($mailbox) { $mailbox.RecipientTypeDetails } else { "" }
            ForwardStatus       = if ($mailbox) { $mailbox.DeliverToMailboxAndForward } else { "" }
            ForwardAddress      = if ($mailbox) { $mailbox.ForwardingAddress } else { "" }
            ForwardSMTP         = if ($mailbox) { $mailbox.ForwardingSMTPAddress } else { "" }
            SignInBlocked       = -not [bool]$user.AccountEnabled
            LicenseStatus       = ($user.AssignedLicenses.Count -gt 0)
        })
    }

    $outRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $outFile = Join-Path -Path $outRoot -ChildPath "MFAResults.csv"

    $report | Sort-Object Name | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $outFile

    if (-not $SkipGridView) {
        $report |
            Select-Object User,Name,MFAStatus,CATargeted,RecentMFARequired,MailboxType,SignInBlocked,LicenseStatus |
            Sort-Object Name |
            Out-GridView
    }

    Write-Host "Report written to: $outFile"
}
finally {
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
    Disconnect-MgGraph -ErrorAction SilentlyContinue
}
