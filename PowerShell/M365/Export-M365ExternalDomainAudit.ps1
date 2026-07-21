[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$Days = 30
)

# Connect
Connect-ExchangeOnline

try {
    # --- Time window (UTC) ---
    $start = (Get-Date).AddDays(-$Days).ToUniversalTime()
    $end   = (Get-Date).ToUniversalTime()

    # --- Tenant domains (lowercase strings) ---
    $tenantDomains =
        (Get-AcceptedDomain | Select-Object -ExpandProperty DomainName) +
        @(
            # Optional extras you may want to treat as internal
            (Get-OrganizationConfig).OrganizationId.ToString().Split('/')[-1] + '.onmicrosoft.com'
        )
    $tenantDomains = $tenantDomains | ForEach-Object { $_.ToLower() } | Sort-Object -Unique

    # --- Streaming audit search ---
    $sessionId = [guid]::NewGuid().ToString()
    $emailRegex = '\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b'

    # mapping: domain => HashSet[email]
    $mapping = @{}

    do {
        $batch = Search-UnifiedAuditLog `
            -StartDate $start `
            -EndDate   $end `
            -RecordType 25 `
            -ResultSize 5000 `
            -SessionId $sessionId `
            -SessionCommand ReturnLargeSet

        if ($batch) {
            foreach ($log in $batch) {
                # AuditData is normally a JSON string already
                $text = if ($log.AuditData -is [string]) { $log.AuditData } else { ($log.AuditData | ConvertTo-Json -Depth 5) }

                [regex]::Matches($text, $emailRegex) | ForEach-Object {
                    $local  = $_.Groups[1].Value
                    $domain = $_.Groups[2].Value.ToLower()
                    if (-not $domain) { return }

                    # Skip tenant/internal domains
                    if ($tenantDomains -contains $domain) { return }

                    $emailFull = ("$local@$domain").ToLower()

                    if (-not $mapping.ContainsKey($domain)) {
                        $mapping[$domain] = New-Object 'System.Collections.Generic.HashSet[string]'
                    }
                    # HashSet prevents duplicates
                    $null = $mapping[$domain].Add($emailFull)
                }
            }
        }

        Start-Sleep -Milliseconds 250   # be nice to throttling
    }
    while ($batch -and $batch.Count -gt 0)

    # --- Aggregate & export ---
    $rows = foreach ($kv in $mapping.GetEnumerator() | Sort-Object Key) {
        [PSCustomObject]@{
            Domain = $kv.Key
            Users  = ($kv.Value | Sort-Object) -join ';'
        }
    }

    $outRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $outFile = Join-Path $outRoot 'external-domains-users.csv'
    $rows | Export-Csv -Path $outFile -NoTypeInformation -Encoding UTF8

    Write-Host ("Processed {0} domains; wrote {1}" -f $rows.Count, $outFile)
}
finally {
    Disconnect-ExchangeOnline -Confirm:$false
}
