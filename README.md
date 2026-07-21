# KeyStone Tools

This repository contains KeyStone Solutions internal tooling. The PowerShell utilities live under [PowerShell/](PowerShell/), grouped by topic. The summaries below list each script, a short description, and basic usage notes; paths are relative to the repository root.

## PowerShell

**Active Directory** — [PowerShell/Active Directory/](PowerShell/Active%20Directory/)
- Collect-ADInventory.ps1: Collect AD domain inventory for `AD Full Name`, `AD Short Name`, `AD Servers`, `DNS Servers`, `DHCP Servers`, `AD Level`, `Primary Domain Controller`, `Global Catalog Server(s)`, `Domain Admins`, `Schema Master`, and `Read Only Domain Controllers`. Console output and JSON export are both minimal: hostnames only for server lists and `Display Name [username]` for domain admins. The script is read-only unless `-OutputPath` is used to export JSON. Use `-PassThru` to return the same minimal object and `-Interactive` to confirm DNS/DHCP server selections with `Out-GridView`.
- Export-UserLogonLogoffAudit.ps1: Export a user's logon/logoff events from the Security event log to CSV. Prompts for username and date range. Requires elevated (Administrator) PowerShell.
- Get-DefaultDomainAdministratorUsageAudit.ps1: Audit RID 500 built-in domain administrator usage on the local DC by default, or across all DCs with `-AllDomainControllers`. Includes Security log activity plus DC scheduled task and service dependencies, exports a multi-sheet Excel workbook when `ImportExcel` is available or falls back to a folder of CSV files, and prints a disablement checklist.
- Protect-UnprotectedOrganizationalUnits.ps1: List OUs that are not protected from accidental deletion, show their ADUC-style path, and optionally enable protection interactively or with `-AutoProtect`.
- Reset-ComputerTrustRelationship.ps1: Reset the machine account password against a specified Domain Controller. Requires elevated PowerShell and domain admin credentials. Optional `-Restart` switch.

**DNS** — [PowerShell/DNS/](PowerShell/DNS/)
- Get-DomainEmailAuthenticationRecords.ps1: Check MX, DMARC, SPF, DKIM, BIMI, MTA-STS, and TLS-RPT records for one or more domains. Run without parameters to be prompted for a single domain interactively, or pass `-Domains` for one or more domains (comma-delimited or array). Use `-DkimSelectors` to override the default selectors (`selector1`, `selector2`, `google`). Outputs a summary table and detailed per-domain results to the console. Use `-CsvPath` to export full results to CSV.

**Group Policy** — [PowerShell/Group Policy/](PowerShell/Group%20Policy/)
- Get-GpoNetworkLocations.ps1: Parse GPO reports (XML) and extract drive mappings, folder redirections, and roaming profile settings for reporting.
- New-PseudoHomeFolder.ps1: Logon script to create per-user folders on a file share and grant the user Full Control without breaking inheritance. Intended for SYSVOL logon deployment. **Configure the `$serverpath` variable at the top of the script for each environment before deploying.**

**M365** — [PowerShell/M365/](PowerShell/M365/)
Exchange / Audit
- Export-M365SuspiciousActivityAudit.ps1: Aggregate mailbox and sign-in audit data for a list of users and generate an Excel workbook (requires ImportExcel, ExchangeOnlineManagement, Microsoft.Graph modules). Use `-UsersCsv`, `-DaysBack`, and `-ClientName` parameters. `-ClientName` sets the prefix of the output filename (default: `Audit`).
- Get-M365MfaReport.ps1: Generate MFA/sign-in related reporting (configurable lookback days). Contains helpers to evaluate conditional access policies.
- Get-M365AdminRoleAssignments.ps1: List every Entra ID admin (directory) role that has assignments and, in a single grouped console report, the users assigned to each role (requires Microsoft.Graph modules; scopes `RoleManagement.Read.Directory`, `User.Read.All`, `Directory.Read.All`). Roles with no assignments are omitted; group/service-principal assignments are labelled by principal type. Use `-IncludeEligible` to also include PIM eligible assignments, `-CsvPath` to export, and `-SkipGridView` to suppress the grid window.
- Export-M365ExternalDomainAudit.ps1: Search unified audit logs for external domains referenced in Teams/Exchange audit records and export `external-domains-users.csv`.

SharePoint
- M365/SharePoint/SharePoint-Download.ps1: Download a SharePoint Online document library or all non-system libraries to a local path and append file metadata to `Metadata.csv`. Requires PowerShell 7.2+, PnP.PowerShell, and a PnP Entra app registration. Pass `-SourceSiteURL` and `-ClientId` (required), and optionally `-LibraryName` (default: `Documents`) and `-DownloadPath` (default: `C:\Site Downloads`).

**Windows** — [PowerShell/Windows/](PowerShell/Windows/)
- Get-NetworkConfiguration.ps1: Enhanced ipconfig-style output including DNS, gateways, and optional JSON/CSV export. Supports `-InterfaceAlias`, `-IncludeIPv6`, `-AsJson`, `-AsCsv`.
- Get-WindowsTimeStatus.ps1: Quick check for Windows time service/NTP configuration, scheduled sync tasks, and last run status.

Notes
- Many scripts require modules (ExchangeOnlineManagement, Microsoft.Graph, ImportExcel, etc.) and/or elevated privileges. See individual script header comments for module and permission requirements.
- Before running M365 scripts, authenticate with the relevant modules (Connect-ExchangeOnline / Connect-MgGraph) as needed.
