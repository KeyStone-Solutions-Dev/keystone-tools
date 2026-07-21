<#
.SYNOPSIS
Resets the machine account password against a chosen domain controller.

.PARAMETER DomainController
Target DC to perform the reset.

.PARAMETER Domain
Domain name for the credential prompt.

.PARAMETER Restart
Optional switch to reboot after a successful reset.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$DomainController,

    [Parameter(Mandatory = $true)]
    [string]$Domain,

    [switch]$Restart,

    [string]$LogPath = "$env:ProgramData\TrustRepair.log"
)

$ErrorActionPreference = 'Stop'

function Assert-Admin {
    $current = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $current.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        throw 'Run this script from an elevated PowerShell session.'
    }
}

function Write-Log {
    param([string]$Message)
    $timestamp = (Get-Date).ToString('s')
    Add-Content -Path $LogPath -Value "$timestamp`t$Message"
}

try {
    Assert-Admin
    Write-Log "Starting trust repair on $env:COMPUTERNAME"

    if (-not (Get-CimInstance Win32_ComputerSystem).PartOfDomain) {
        throw 'This machine is not joined to a domain.'
    }

    Write-Log "Testing network connectivity to $DomainController"
    if (-not (Test-Connection -ComputerName $DomainController -Count 1 -Quiet)) {
        throw "Cannot reach domain controller $DomainController."
    }

    $cred = Get-Credential -Message "Enter domain admin credentials for $Domain"
    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Reset machine password against $DomainController")) {
        Write-Log "Resetting machine password via $DomainController"
        Reset-ComputerMachinePassword -Server $DomainController -Credential $cred
        Write-Log 'Machine password reset succeeded'
    }

    if ($Restart) {
        Write-Log 'Restart requested; rebooting now'
        Restart-Computer -Force
    } else {
        Write-Log 'Operation complete; restart recommended to finalize'
        Write-Host 'Restart the computer to complete the trust repair.' -ForegroundColor Yellow
    }
}
catch {
    Write-Log "Failed: $_"
    throw
}
