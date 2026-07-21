[CmdletBinding()]
param(
    [Parameter(HelpMessage = "Domain list. Supports comma-delimited input.")]
    [string[]]$Domains,

    [Parameter(HelpMessage = "Path to export CSV output.")]
    [string]$CsvPath,

    [Parameter(HelpMessage = "DKIM selectors to check.")]
    [string[]]$DkimSelectors = @('selector1','selector2','google')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $Domains) {
    $rawDomain = Read-Host 'Enter domain to check'
    $Domains = @($rawDomain)
}

function Resolve-TxtRecord {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    try {
        $records = Resolve-DnsName -Name $Name -Type TXT -ErrorAction Stop
    }
    catch {
        try {
            $records = Resolve-DnsName -Name $Name -Type CNAME -ErrorAction Stop
        }
        catch {
            return [pscustomobject]@{
                Found    = $false
                Value    = $null
                Record   = $Name
                Error    = $_.Exception.Message
            }
        }
    }

    $txtData = $records |
        Where-Object { $_.PSObject.Properties.Name -contains 'Strings' -and $_.Strings } |
        ForEach-Object { ($_.Strings -join '') }

    if ($txtData) {
        return [pscustomobject]@{
            Found    = $true
            Value    = ($txtData -join ' | ')
            Record   = $Name
            Error    = $null
        }
    }

    $cnameData = $records |
        Where-Object { $_.PSObject.Properties.Name -contains 'NameHost' -and $_.NameHost } |
        Select-Object -ExpandProperty NameHost -Unique

    if ($cnameData) {
        return [pscustomobject]@{
            Found    = $true
            Value    = ('CNAME -> ' + ($cnameData -join ' | '))
            Record   = $Name
            Error    = $null
        }
    }

    return [pscustomobject]@{
        Found    = $false
        Value    = $null
        Record   = $Name
        Error    = 'No TXT or CNAME data returned.'
    }
}

function Resolve-MxRecord {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    try {
        $records = Resolve-DnsName -Name $Name -Type MX -ErrorAction Stop
    }
    catch {
        return [pscustomobject]@{
            Found  = $false
            Value  = $null
            Record = $Name
            Error  = $_.Exception.Message
        }
    }

    $mxData = $records |
        Where-Object { $_.PSObject.Properties.Name -contains 'NameExchange' -and $_.NameExchange } |
        Sort-Object Preference |
        ForEach-Object { "$($_.Preference) $($_.NameExchange)" }

    if ($mxData) {
        return [pscustomobject]@{
            Found  = $true
            Value  = ($mxData -join ' | ')
            Record = $Name
            Error  = $null
        }
    }

    return [pscustomobject]@{
        Found  = $false
        Value  = $null
        Record = $Name
        Error  = 'No MX records returned.'
    }
}

$normalizedDomains = foreach ($item in $Domains) {
    if ([string]::IsNullOrWhiteSpace($item)) { continue }

    foreach ($piece in ($item -split ',')) {
        $domain = $piece.Trim().ToLowerInvariant()
        if ($domain) { $domain }
    }
}

$normalizedDomains = $normalizedDomains | Sort-Object -Unique

if (-not $normalizedDomains) {
    throw 'No valid domains were provided.'
}

$normalizedSelectors = foreach ($selector in $DkimSelectors) {
    if ([string]::IsNullOrWhiteSpace($selector)) { continue }
    $value = $selector.Trim().ToLowerInvariant()
    if ($value) { $value }
}

$normalizedSelectors = $normalizedSelectors | Sort-Object -Unique

if (-not $normalizedSelectors) {
    throw 'No valid DKIM selectors were provided.'
}

$results = foreach ($domain in $normalizedDomains) {
    Write-Host "Checking $domain..." -ForegroundColor Cyan

    $mx     = Resolve-MxRecord  -Name $domain
    $dmarc  = Resolve-TxtRecord -Name "_dmarc.$domain"
    $bimi   = Resolve-TxtRecord -Name "_bimi.$domain"
    $mtaSts = Resolve-TxtRecord -Name "_mta-sts.$domain"
    $tlsRpt = Resolve-TxtRecord -Name "_smtp._tls.$domain"

    $spf = Resolve-TxtRecord -Name $domain
    if ($spf.Found -and $spf.Value) {
        $spfValues = ($spf.Value -split ' \| ') | Where-Object { $_ -match '(?i)^v=spf1' }
        if ($spfValues) {
            $spf.Value = $spfValues -join ' | '
            $spf.Found = $true
            $spf.Error = $null
        }
        else {
            $spf.Found = $false
            $spf.Value = $null
            $spf.Error = 'TXT records found, but no SPF policy (v=spf1) was present.'
        }
    }

    $dkimDetails = foreach ($selector in $normalizedSelectors) {
        $dkimQuery = "$selector._domainkey.$domain"
        $dkim = Resolve-TxtRecord -Name $dkimQuery

        [pscustomobject]@{
            DKIMSelector = $selector
            DKIMRecord   = $dkim.Record
            DKIMFound    = $dkim.Found
            DKIMValue    = $dkim.Value
            DKIMError    = $dkim.Error
        }
    }

    $dkimSummary = $dkimDetails |
        ForEach-Object {
            if ($_.DKIMFound) { "{0}=Found" -f $_.DKIMSelector }
            else              { "{0}=NotFound" -f $_.DKIMSelector }
        }

    [pscustomobject]@{
        Domain       = $domain
        MXRecord     = $mx.Record
        MXFound      = $mx.Found
        MXValue      = $mx.Value
        MXError      = $mx.Error
        DMARCRecord  = $dmarc.Record
        DMARCFound   = $dmarc.Found
        DMARCValue   = $dmarc.Value
        DMARCError   = $dmarc.Error
        SPFRecord    = $spf.Record
        SPFFound     = $spf.Found
        SPFValue     = $spf.Value
        SPFError     = $spf.Error
        DKIMFound    = ($dkimDetails.DKIMFound -contains $true)
        DKIMSummary  = ($dkimSummary -join '; ')
        DKIMDetails  = ($dkimDetails | ConvertTo-Json -Compress -Depth 4)
        BIMIRecord   = $bimi.Record
        BIMIFound    = $bimi.Found
        BIMIValue    = $bimi.Value
        BIMIError    = $bimi.Error
        MTASTSRecord = $mtaSts.Record
        MTASTSFound  = $mtaSts.Found
        MTASTSValue  = $mtaSts.Value
        MTASTSError  = $mtaSts.Error
        TLSRPTRecord = $tlsRpt.Record
        TLSRPTFound  = $tlsRpt.Found
        TLSRPTValue  = $tlsRpt.Value
        TLSRPTError  = $tlsRpt.Error
        CheckedAt    = (Get-Date)
    }
}

$results | Format-Table Domain, MXFound, DMARCFound, SPFFound, DKIMFound, BIMIFound, MTASTSFound, TLSRPTFound -Wrap -AutoSize

Write-Host ''
Write-Host 'Detailed Results:' -ForegroundColor Yellow
$results |
    Sort-Object Domain |
    ForEach-Object {
        Format-List -InputObject $_ -Property `
            Domain, `
            MXRecord, MXFound, MXValue, MXError, `
            DMARCRecord, DMARCFound, DMARCValue, DMARCError, `
            SPFRecord, SPFFound, SPFValue, SPFError, `
            DKIMFound, DKIMSummary, `
            BIMIRecord, BIMIFound, BIMIValue, BIMIError, `
            MTASTSRecord, MTASTSFound, MTASTSValue, MTASTSError, `
            TLSRPTRecord, TLSRPTFound, TLSRPTValue, TLSRPTError, `
            CheckedAt

        Write-Host 'DKIM Details:' -ForegroundColor DarkYellow
        $dkimItems = $_.DKIMDetails | ConvertFrom-Json
        $dkimItems | Format-Table DKIMSelector, DKIMRecord, DKIMFound, DKIMValue, DKIMError -Wrap -AutoSize
        Write-Host ''
    }

if ($CsvPath) {
    $results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV exported: $CsvPath" -ForegroundColor Green
}
