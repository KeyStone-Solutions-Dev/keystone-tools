<#
.SYNOPSIS
Provides a richer ipconfig-style view with DNS details.

.PARAMETER InterfaceAlias
Limit output to specific interface aliases (supports wildcards).

.PARAMETER IncludeIPv6
Include IPv6 addresses and gateways.

.PARAMETER AsJson
Emit JSON instead of a table; useful for scripting.

.PARAMETER AsCsv
Emit CSV; requires an OutputPath or writes to console.

.PARAMETER OutputPath
Path to write JSON/CSV output.
#>
[CmdletBinding()]
param(
    [string[]]$InterfaceAlias,
    [switch]$IncludeIPv6,
    [switch]$AsJson,
    [switch]$AsCsv,
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'

if ($AsJson -and $AsCsv) {
    throw 'Choose either -AsJson or -AsCsv, not both.'
}

# Collect network configuration
$ipConfigs = if ($InterfaceAlias) {
    Get-NetIPConfiguration -InterfaceAlias $InterfaceAlias
} else {
    Get-NetIPConfiguration
}

$dnsConfigs = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE'

$results = foreach ($ip in $ipConfigs) {
    $dnsInfo = $dnsConfigs | Where-Object { $_.Description -eq $ip.InterfaceDescription }

    $ipv4Addrs = $ip.IPv4Address | ForEach-Object { $_.IPAddress } | Where-Object { $_ }
    $ipv4Cidr  = $ip.IPv4Address | ForEach-Object { $_.PrefixLength } | Where-Object { $_ }
    $ipv4Gw    = $ip.IPv4DefaultGateway | ForEach-Object { $_.NextHop } | Where-Object { $_ }

    $dhcpEnabled = ($ip.IPv4Address | Where-Object { $_.PrefixOrigin -eq 'Dhcp' }).Count -gt 0

    $dnsServers = $ip.DNSServer.ServerAddresses | Where-Object { $_ }

    $obj = [PSCustomObject]@{
        InterfaceAlias    = $ip.InterfaceAlias
        InterfaceDesc     = $ip.InterfaceDescription
        IPv4              = ($ipv4Addrs -join ', ')
        CIDR              = ($ipv4Cidr -join ', ')
        Gateway           = ($ipv4Gw -join ', ')
        'DHCP Enabled'    = $dhcpEnabled
        'DHCP Server'     = ($ip.DhcpServer.ServerAddresses -join ', ')
        'DNS Servers'     = ($dnsServers -join ', ')
        'DNS Suffix'      = $dnsInfo.DNSDomain
        'DNS Search List' = ($dnsInfo.DNSDomainSuffixSearchOrder -join ', ')
    }

    if ($IncludeIPv6) {
        $ipv6Addrs = $ip.IPv6Address | ForEach-Object { $_.IPAddress } | Where-Object { $_ }
        $ipv6Gw    = $ip.IPv6DefaultGateway | ForEach-Object { $_.NextHop } | Where-Object { $_ }
        $obj | Add-Member -NotePropertyName IPv6 -NotePropertyValue ($ipv6Addrs -join ', ')
        $obj | Add-Member -NotePropertyName IPv6Gateway -NotePropertyValue ($ipv6Gw -join ', ')
    }

    $obj
}

if ($AsJson) {
    $json = $results | ConvertTo-Json -Depth 4
    if ($OutputPath) { $json | Set-Content -Path $OutputPath } else { $json }
    return
}

if ($AsCsv) {
    if ($OutputPath) {
        $results | Export-Csv -Path $OutputPath -NoTypeInformation
    } else {
        $results | Export-Csv -Path (Join-Path $env:TEMP 'Get-NetworkConfiguration.csv') -NoTypeInformation -Force
        Write-Warning 'No OutputPath specified; wrote CSV to temp file.'
    }
    return
}

$results | Format-Table -AutoSize
