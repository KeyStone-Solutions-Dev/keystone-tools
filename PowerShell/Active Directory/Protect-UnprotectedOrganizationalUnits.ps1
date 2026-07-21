<#
.SYNOPSIS
Finds Organizational Units that are not protected from accidental deletion and optionally enables protection.

.DESCRIPTION
Queries Active Directory for all OUs where ProtectedFromAccidentalDeletion is not enabled,
displays their ADUC-style canonical path, and prompts once whether to enable protection on all discovered OUs.

.PARAMETER SearchBase
Optional distinguished name to limit the search scope.

.PARAMETER IncludeSystemContainers
Include OUs under CN=System when a search base is not specified.

.PARAMETER AutoProtect
Enable protection on all matching OUs without prompting.

.EXAMPLE
.\Protect-UnprotectedOrganizationalUnits.ps1

.EXAMPLE
.\Protect-UnprotectedOrganizationalUnits.ps1 -SearchBase "OU=Corp,DC=contoso,DC=com"

.EXAMPLE
.\Protect-UnprotectedOrganizationalUnits.ps1 -AutoProtect
#>
[CmdletBinding()]
param(
    [string]$SearchBase,
    [switch]$IncludeSystemContainers,
    [switch]$AutoProtect
)

$ErrorActionPreference = 'Stop'

function Assert-ActiveDirectoryModule {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw 'The ActiveDirectory module is required. Run this on a domain controller or a system with RSAT installed.'
    }

    Import-Module ActiveDirectory
}

function Test-Yes {
    param([string]$Value)

    return $Value -match '^(?i)y(es)?$'
}

function Get-CanonicalOuPath {
    param([string]$CanonicalName)

    if ([string]::IsNullOrWhiteSpace($CanonicalName)) {
        return $null
    }

    return $CanonicalName.TrimEnd('/')
}

function Get-DisplayPath {
    param($OrganizationalUnit)

    $canonicalPath = Get-CanonicalOuPath -CanonicalName $OrganizationalUnit.CanonicalName
    if (-not [string]::IsNullOrWhiteSpace($canonicalPath)) {
        return $canonicalPath
    }

    return $OrganizationalUnit.DistinguishedName
}

Assert-ActiveDirectoryModule

$getOuParams = @{
    Filter     = '*'
    Properties = @('CanonicalName', 'ProtectedFromAccidentalDeletion', 'DistinguishedName')
}

if ($SearchBase) {
    $getOuParams.SearchBase = $SearchBase
}

$ous = Get-ADOrganizationalUnit @getOuParams | Sort-Object CanonicalName

if (-not $IncludeSystemContainers -and -not $SearchBase) {
    $ous = $ous | Where-Object { $_.DistinguishedName -notlike '*,CN=System,*' }
}

$unprotectedOus = $ous | Where-Object { -not $_.ProtectedFromAccidentalDeletion }

if (-not $unprotectedOus) {
    Write-Host 'All discovered OUs are already protected from accidental deletion.' -ForegroundColor Green
    return
}

Write-Host ''
Write-Host 'Unprotected OUs:' -ForegroundColor Yellow
$unprotectedOus |
    Select-Object @{
        Name       = 'ADUC Path'
        Expression = { Get-CanonicalOuPath -CanonicalName $_.CanonicalName }
    }, DistinguishedName |
    Format-Table -AutoSize

Write-Host ''

$protectedCount = 0
$failedCount = 0
$failedOus = [System.Collections.Generic.List[object]]::new()
$proceed = $AutoProtect

if (-not $AutoProtect) {
    $response = Read-Host "Protect all $($unprotectedOus.Count) listed OUs? (y/n)"
    $proceed = Test-Yes -Value $response
}

if (-not $proceed) {
    Write-Host 'No changes made.' -ForegroundColor Yellow
    return
}

foreach ($ou in $unprotectedOus) {
    $ouPath = Get-DisplayPath -OrganizationalUnit $ou

    try {
        Set-ADOrganizationalUnit `
            -Identity $ou.DistinguishedName `
            -ProtectedFromAccidentalDeletion $true `
            -Confirm:$false `
            -ErrorAction Stop

        $updatedOu = Get-ADOrganizationalUnit `
            -Identity $ou.DistinguishedName `
            -Properties ProtectedFromAccidentalDeletion, CanonicalName, DistinguishedName `
            -ErrorAction Stop

        if (-not $updatedOu.ProtectedFromAccidentalDeletion) {
            throw 'The OU update completed, but the protection flag is still disabled.'
        }

        Write-Host "Protected $(Get-DisplayPath -OrganizationalUnit $updatedOu)" -ForegroundColor Green
        $protectedCount++
    }
    catch {
        $message = $_.Exception.Message
        if ([string]::IsNullOrWhiteSpace($message)) {
            $message = $_.ToString()
        }

        Write-Host "Failed to protect ${ouPath}: $message" -ForegroundColor Red
        $failedOus.Add([PSCustomObject]@{
            Path              = $ouPath
            DistinguishedName = $ou.DistinguishedName
            Error             = $message
        }) | Out-Null
        $failedCount++
    }
}

Write-Host ''
Write-Host "Summary: $($unprotectedOus.Count) found, $protectedCount protected, $failedCount failed."

if ($failedOus.Count -gt 0) {
    Write-Host ''
    Write-Host 'Failed OUs:' -ForegroundColor Red
    $failedOus | Format-Table -AutoSize
}
