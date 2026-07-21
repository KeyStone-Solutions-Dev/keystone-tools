<#
.SYNOPSIS
Collects minimal Active Directory inventory for domain, DNS, DHCP, and core FSMO details.

.DESCRIPTION
This script is intended to run on a domain controller or a management host with the
ActiveDirectory module installed. It is read-only against Active Directory, DNS, and
DHCP. The only write operation is optional local JSON export when -OutputPath is used.

.PARAMETER Interactive
Uses Out-GridView to let you confirm the discovered DNS and DHCP server lists when
available. Automatic discovery still runs first.

.PARAMETER OutputPath
Optional local path for exporting the inventory as JSON.

.PARAMETER PassThru
Returns the same minimal inventory object that is shown in the console and written to
JSON. If omitted, the script writes only the human-readable summary and optional JSON export.

.EXAMPLE
.\Collect-ADInventory.ps1

.EXAMPLE
.\Collect-ADInventory.ps1 -Interactive

.EXAMPLE
.\Collect-ADInventory.ps1 -OutputPath .\ad-inventory.json

.EXAMPLE
.\Collect-ADInventory.ps1 -PassThru
#>
[CmdletBinding()]
[OutputType([pscustomobject])]
param(
    [switch]$Interactive,
    [string]$OutputPath,
    [switch]$PassThru
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Assert-ModuleAvailable {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if (-not (Get-Module -ListAvailable -Name $Name)) {
        throw "The $Name module is required. Run this on a domain controller or a system with RSAT installed."
    }
}

function Import-OptionalModule {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if (-not (Get-Module -ListAvailable -Name $Name)) {
        return $false
    }

    Import-Module $Name -ErrorAction Stop
    return $true
}

function Show-ServerSelection {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Candidates
    )

    if (-not $Interactive) {
        return @($Candidates)
    }

    if (-not (Get-Command Out-GridView -ErrorAction SilentlyContinue)) {
        Write-Warning 'Interactive mode was requested, but Out-GridView is not available. Continuing with automatic discovery.'
        return @($Candidates)
    }

    return @(
        $Candidates |
            Sort-Object ServerName, Fqdn -Unique |
            Out-GridView -Title $Title -PassThru
    )
}

function Get-ServerLookupTable {
    $serverComputers = Get-ADComputer -LDAPFilter '(&(objectCategory=computer)(operatingSystem=*Server*))' -Properties DNSHostName, IPv4Address, OperatingSystem, Description

    $byName = @{}
    $byFqdn = @{}

    foreach ($computer in $serverComputers) {
        if ($computer.Name) {
            $byName[$computer.Name.ToUpperInvariant()] = $computer
        }

        if ($computer.DNSHostName) {
            $byFqdn[$computer.DNSHostName.ToUpperInvariant()] = $computer
        }
    }

    return @{
        ByName = $byName
        ByFqdn = $byFqdn
    }
}

function Get-DomainControllerMap {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$DomainControllers
    )

    $map = @{}

    foreach ($domainController in $DomainControllers) {
        if ($domainController.HostName) {
            $map[$domainController.HostName.ToUpperInvariant()] = $domainController
        }

        if ($domainController.Name) {
            $map[$domainController.Name.ToUpperInvariant()] = $domainController
        }
    }

    return $map
}

function Resolve-InventoryServer {
    param(
        [AllowNull()]
        [string]$Identity,

        [Parameter(Mandatory = $true)]
        [hashtable]$Lookup,

        [Parameter(Mandatory = $true)]
        [hashtable]$DomainControllerMap,

        [string]$Role,
        [string]$DiscoveryMethod,
        [string]$Notes
    )

    if ([string]::IsNullOrWhiteSpace($Identity)) {
        return $null
    }

    $normalizedIdentity = $Identity.Trim().TrimEnd('.')
    $shortName = ($normalizedIdentity -split '\.')[0]
    $computer = $null
    $domainController = $null

    if ($Lookup.ByFqdn.ContainsKey($normalizedIdentity.ToUpperInvariant())) {
        $computer = $Lookup.ByFqdn[$normalizedIdentity.ToUpperInvariant()]
    }
    elseif ($Lookup.ByName.ContainsKey($shortName.ToUpperInvariant())) {
        $computer = $Lookup.ByName[$shortName.ToUpperInvariant()]
    }

    if ($DomainControllerMap.ContainsKey($normalizedIdentity.ToUpperInvariant())) {
        $domainController = $DomainControllerMap[$normalizedIdentity.ToUpperInvariant()]
    }
    elseif ($DomainControllerMap.ContainsKey($shortName.ToUpperInvariant())) {
        $domainController = $DomainControllerMap[$shortName.ToUpperInvariant()]
    }

    $descriptionParts = [System.Collections.Generic.List[string]]::new()

    if ($Role) {
        $descriptionParts.Add($Role) | Out-Null
    }

    if ($domainController) {
        $descriptionParts.Add('Domain Controller') | Out-Null
        if ($domainController.IsGlobalCatalog) {
            $descriptionParts.Add('Global Catalog') | Out-Null
        }
        if ($domainController.IsReadOnly) {
            $descriptionParts.Add('Read Only Domain Controller') | Out-Null
        }
    }

    if ($Notes) {
        $descriptionParts.Add($Notes) | Out-Null
    }
    elseif ($computer -and $computer.Description) {
        $descriptionParts.Add($computer.Description) | Out-Null
    }

    return [PSCustomObject]@{
        ServerName      = if ($computer -and $computer.Name) { $computer.Name } elseif ($domainController -and $domainController.Name) { $domainController.Name } else { $shortName }
        Fqdn            = if ($computer -and $computer.DNSHostName) { $computer.DNSHostName } elseif ($domainController -and $domainController.HostName) { $domainController.HostName } else { $normalizedIdentity }
        IPv4Address     = if ($domainController -and $domainController.IPv4Address) { $domainController.IPv4Address } elseif ($computer -and $computer.IPv4Address) { $computer.IPv4Address } else { $null }
        Site            = if ($domainController) { $domainController.Site } else { $null }
        OperatingSystem = if ($computer) { $computer.OperatingSystem } else { $null }
        Description     = ($descriptionParts | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique) -join '; '
        DiscoveryMethod = $DiscoveryMethod
    }
}

function Get-InventoryServerSummaryText {
    param(
        [AllowNull()]
        [object[]]$Servers
    )

    if (-not $Servers -or $Servers.Count -eq 0) {
        return 'None found'
    }

    return (($Servers | ForEach-Object {
        $fqdn = if ($_.PSObject.Properties.Match('Fqdn').Count -gt 0) { $_.Fqdn } else { $null }
        $serverName = if ($_.PSObject.Properties.Match('ServerName').Count -gt 0) { $_.ServerName } else { $null }

        if ([string]::IsNullOrWhiteSpace($fqdn)) {
            $fqdn = $serverName
        }

        $fqdn
    }) -join '; ')
}

function Get-DomainAdminsSummaryText {
    param(
        [AllowNull()]
        [object[]]$Admins
    )

    if (-not $Admins -or $Admins.Count -eq 0) {
        return 'None found'
    }

    return (($Admins | ForEach-Object {
        if ($_.DisplayName -and $_.SamAccountName) {
            '{0} [{1}]' -f $_.DisplayName, $_.SamAccountName
        }
        elseif ($_.SamAccountName) {
            $_.SamAccountName
        }
        else {
            $_.DisplayName
        }
    }) -join '; ')
}

function Get-InventoryDomainControllers {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$DomainControllers
    )

    foreach ($domainController in $DomainControllers | Sort-Object HostName) {
        [PSCustomObject]@{
            ServerName      = $domainController.Name
            Fqdn            = $domainController.HostName
            Site            = $domainController.Site
            IPv4Address     = $domainController.IPv4Address
            IsGlobalCatalog = [bool]$domainController.IsGlobalCatalog
            IsReadOnly      = [bool]$domainController.IsReadOnly
            OperationMaster = ($domainController.OperationMasterRoles -join ', ')
        }
    }
}

function Get-InventoryDnsServers {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ZoneName,

        [Parameter(Mandatory = $true)]
        [object[]]$DomainControllers,

        [Parameter(Mandatory = $true)]
        [hashtable]$Lookup,

        [Parameter(Mandatory = $true)]
        [hashtable]$DomainControllerMap
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    if (Import-OptionalModule -Name DnsServer) {
        try {
            $nsRecords = Get-DnsServerResourceRecord -ZoneName $ZoneName -RRType NS -ErrorAction Stop
            foreach ($record in $nsRecords) {
                $server = Resolve-InventoryServer -Identity $record.RecordData.NameServer -Lookup $Lookup -DomainControllerMap $DomainControllerMap -Role 'DNS Server' -DiscoveryMethod 'NS records in AD-integrated DNS zone'
                if ($server -and $seen.Add($server.Fqdn)) {
                    $results.Add($server) | Out-Null
                }
            }
        }
        catch {
            Write-Warning "Unable to query DNS NS records: $($_.Exception.Message)"
        }
    }

    if ($results.Count -eq 0) {
        foreach ($domainController in $DomainControllers) {
            $server = Resolve-InventoryServer -Identity $domainController.HostName -Lookup $Lookup -DomainControllerMap $DomainControllerMap -Role 'DNS Server' -DiscoveryMethod 'Fallback to domain controllers' -Notes 'Auto-fallback because authoritative DNS discovery was unavailable.'
            if ($server -and $seen.Add($server.Fqdn)) {
                $results.Add($server) | Out-Null
            }
        }
    }

    return @($results)
}

function Get-InventoryDhcpServers {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Lookup,

        [Parameter(Mandatory = $true)]
        [hashtable]$DomainControllerMap
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    if (Import-OptionalModule -Name DhcpServer) {
        try {
            $authorizedServers = Get-DhcpServerInDC -ErrorAction Stop
            foreach ($entry in $authorizedServers) {
                $identity = if ($entry.DnsName) { $entry.DnsName } else { $entry.IPAddress }
                $server = Resolve-InventoryServer -Identity $identity -Lookup $Lookup -DomainControllerMap $DomainControllerMap -Role 'DHCP Server' -DiscoveryMethod 'Get-DhcpServerInDC' -Notes 'Authorized in Active Directory.'
                if ($server -and $seen.Add($server.Fqdn)) {
                    $results.Add($server) | Out-Null
                }
            }
        }
        catch {
            Write-Warning "Unable to query authorized DHCP servers with Get-DhcpServerInDC: $($_.Exception.Message)"
        }
    }

    if ($results.Count -eq 0) {
        try {
            $netshOutput = @(netsh dhcp show server 2>$null)
            foreach ($line in $netshOutput) {
                if ($line -match '^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([A-Za-z0-9\.\-]+)\s*$') {
                    $server = Resolve-InventoryServer -Identity $matches[2] -Lookup $Lookup -DomainControllerMap $DomainControllerMap -Role 'DHCP Server' -DiscoveryMethod 'netsh dhcp show server' -Notes 'Authorized in Active Directory.'
                    if ($server -and $seen.Add($server.Fqdn)) {
                        if (-not $server.IPv4Address) {
                            $server.PSObject.Properties['IPv4Address'].Value = $matches[1]
                        }
                        $results.Add($server) | Out-Null
                    }
                }
            }
        }
        catch {
            Write-Warning "Unable to query authorized DHCP servers with netsh: $($_.Exception.Message)"
        }
    }

    return @($results)
}

function Get-InventoryDomainAdmins {
    $members = Get-ADGroupMember -Identity 'Domain Admins' -Recursive -ErrorAction Stop

    foreach ($member in $members | Where-Object { $_.ObjectClass -eq 'user' } | Sort-Object SamAccountName) {
        $user = Get-ADUser -Identity $member.DistinguishedName -Properties DisplayName, Mail, Title, Department, Enabled -ErrorAction Stop

        [PSCustomObject]@{
            SamAccountName = $user.SamAccountName
            DisplayName    = $user.DisplayName
        }
    }
}

function Get-ResolvedInventoryRole {
    param(
        [AllowNull()]
        [string]$Identity,

        [Parameter(Mandatory = $true)]
        [hashtable]$Lookup,

        [Parameter(Mandatory = $true)]
        [hashtable]$DomainControllerMap,

        [Parameter(Mandatory = $true)]
        [string]$Role
    )

    return Resolve-InventoryServer -Identity $Identity -Lookup $Lookup -DomainControllerMap $DomainControllerMap -Role $Role -DiscoveryMethod 'Active Directory metadata'
}

function Write-InventorySummary {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Inventory
    )

    Write-Host ''
    Write-Host 'Active Directory Inventory Summary' -ForegroundColor Cyan
    Write-Host ''
    Write-Host ('AD Full Name: {0}' -f $Inventory.'AD Full Name')
    Write-Host ('AD Short Name: {0}' -f $Inventory.'AD Short Name')
    Write-Host ('AD Level: {0}' -f $Inventory.'AD Level')
    Write-Host ''
    Write-Host ('AD Servers: {0}' -f (Get-InventoryServerSummaryText -Servers $Inventory.'AD Servers'))
    Write-Host ('DNS Servers: {0}' -f (Get-InventoryServerSummaryText -Servers $Inventory.'DNS Servers'))
    Write-Host ('DHCP Servers: {0}' -f (Get-InventoryServerSummaryText -Servers $Inventory.'DHCP Servers'))
    Write-Host ''
    Write-Host ('Primary Domain Controller: {0}' -f (Get-InventoryServerSummaryText -Servers @($Inventory.'Primary Domain Controller')))
    Write-Host ('Global Catalog Server(s): {0}' -f (Get-InventoryServerSummaryText -Servers $Inventory.'Global Catalog Server(s)'))
    Write-Host ('Domain Admins: {0}' -f (Get-DomainAdminsSummaryText -Admins $Inventory.'Domain Admins'))
    Write-Host ('Schema Master: {0}' -f (Get-InventoryServerSummaryText -Servers @($Inventory.'Schema Master')))
    Write-Host ('Read Only Domain Controllers: {0}' -f (Get-InventoryServerSummaryText -Servers $Inventory.'Read Only Domain Controllers'))
}

Assert-ModuleAvailable -Name ActiveDirectory
Import-Module ActiveDirectory -ErrorAction Stop

function Convert-ServersToHostNames {
    param(
        [AllowNull()]
        [object[]]$Servers
    )

    if (-not $Servers) {
        return @()
    }

    return @(
        $Servers |
            ForEach-Object {
                if ($_.PSObject.Properties.Match('Fqdn').Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($_.Fqdn)) {
                    $_.Fqdn
                }
                elseif ($_.PSObject.Properties.Match('ServerName').Count -gt 0) {
                    $_.ServerName
                }
            } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Unique
    )
}

$domain = Get-ADDomain -ErrorAction Stop
$forest = Get-ADForest -ErrorAction Stop
$domainControllers = @(Get-ADDomainController -Filter * -ErrorAction Stop)
$lookup = Get-ServerLookupTable
$domainControllerMap = Get-DomainControllerMap -DomainControllers $domainControllers

$adServers = @(Get-InventoryDomainControllers -DomainControllers $domainControllers)
$dnsServers = @(Get-InventoryDnsServers -ZoneName $domain.DNSRoot -DomainControllers $domainControllers -Lookup $lookup -DomainControllerMap $domainControllerMap)
$dhcpServers = @(Get-InventoryDhcpServers -Lookup $lookup -DomainControllerMap $domainControllerMap)

$dnsServers = @(Show-ServerSelection -Title 'Confirm DNS Servers' -Candidates $dnsServers)
$dhcpServers = @(Show-ServerSelection -Title 'Confirm DHCP Servers' -Candidates $dhcpServers)

$globalCatalogServers = @(
    foreach ($domainController in $domainControllers | Where-Object { $_.IsGlobalCatalog }) {
        Get-ResolvedInventoryRole -Identity $domainController.HostName -Lookup $lookup -DomainControllerMap $domainControllerMap -Role 'Global Catalog Server'
    }
)

$readOnlyDomainControllers = @(
    foreach ($domainController in $domainControllers | Where-Object { $_.IsReadOnly }) {
        Get-ResolvedInventoryRole -Identity $domainController.HostName -Lookup $lookup -DomainControllerMap $domainControllerMap -Role 'Read Only Domain Controller'
    }
)

$domainAdmins = @(Get-InventoryDomainAdmins)

$result = [PSCustomObject][ordered]@{
    'AD Full Name'                 = $domain.DNSRoot
    'AD Short Name'                = $domain.NetBIOSName
    'AD Servers'                   = @(Convert-ServersToHostNames -Servers $adServers)
    'DNS Servers'                  = @(Convert-ServersToHostNames -Servers $dnsServers)
    'DHCP Servers'                 = @(Convert-ServersToHostNames -Servers $dhcpServers)
    'AD Level'                     = $domain.DomainMode.ToString()
    'Primary Domain Controller'    = (Convert-ServersToHostNames -Servers @(Get-ResolvedInventoryRole -Identity $domain.PDCEmulator -Lookup $lookup -DomainControllerMap $domainControllerMap -Role 'PDC Emulator') | Select-Object -First 1)
    'Global Catalog Server(s)'     = @(Convert-ServersToHostNames -Servers $globalCatalogServers)
    'Domain Admins'                = $domainAdmins
    'Schema Master'                = (Convert-ServersToHostNames -Servers @(Get-ResolvedInventoryRole -Identity $forest.SchemaMaster -Lookup $lookup -DomainControllerMap $domainControllerMap -Role 'Schema Master') | Select-Object -First 1)
    'Read Only Domain Controllers' = @(Convert-ServersToHostNames -Servers $readOnlyDomainControllers)
}

if ($OutputPath) {
    $outputDirectory = Split-Path -Path $OutputPath -Parent
    if ($outputDirectory -and -not (Test-Path -Path $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory -Force | Out-Null
    }

    $result | ConvertTo-Json -Depth 6 | Set-Content -Path $OutputPath -Encoding UTF8
}

Write-InventorySummary -Inventory $result

if ($PassThru) {
    return $result
}
