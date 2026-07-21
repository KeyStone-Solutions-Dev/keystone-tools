# List GP drive mappings, folder redirection, and roaming profile settings
$Reports = Get-GPO -All | Get-GPOReport -ReportType Xml

$DriveMappings = @()
$FolderRedirections = @()
$RoamingProfiles = @()
$OutputBlocks = @()

function Get-XmlPropertyValue {
    param(
        [object]$Node,
        [string[]]$Names
    )
    if (-not $Node) { return $null }
    foreach ($Name in $Names) {
        $Prop = $Node.PSObject.Properties[$Name]
        if ($Prop -and $Prop.Value) {
            $Value = $Prop.Value
            if ($Value -is [System.Xml.XmlElement]) {
                if ($Value.'#text') { return $Value.'#text' }
                if ($Value.InnerText) { return $Value.InnerText }
            }
            if ($Value -is [System.Xml.XmlAttribute]) { return $Value.Value }
            return [string]$Value
        }
    }
    return $null
}

function Add-DriveMappings {
    param($GpoName, $LinkCount, $Enabled, $Extension)
    $Settings = $Extension.Extension
    if (-not $Settings) { return }
    $Mappings = $Settings.DriveMapSettings.Drive
    foreach ($Mapping in $Mappings) {
        $script:DriveMappings += [pscustomobject]@{
            GPO         = $GpoName
            LinkCount   = $LinkCount
            Enabled     = $Enabled
            DriveLetter = $Mapping.Properties.Letter + ":"
            Label       = $Mapping.Properties.label
            Path        = $Mapping.Properties.Path
        }
    }
}

function Add-FolderRedirects {
    param($GpoName, $LinkCount, $Enabled, $Extension)
    $Settings = $Extension.Extension
    if (-not $Settings) { return }
    $Redirects = $Settings.Folder
    foreach ($Redirect in $Redirects) {
        # Derive a friendlier folder name if the XML value is a namespaced token like "q1:Folder"
        $FolderName = $Redirect.Name
        if ($Redirect.Properties) {
            $FolderName = Get-XmlPropertyValue $Redirect.Properties @("Folder","Name","FolderId","LocalName")
            if (-not $FolderName) { $FolderName = $Redirect.Name }
        } else {
            $FolderName = Get-XmlPropertyValue $Redirect @("LocalName","Name")
        }
        if ($FolderName -match "^[^:]+:(.+)$") { $FolderName = $Matches[1] }

        $Target = Get-XmlPropertyValue $Redirect.Properties @(
            "Path","TargetPath","DestinationPath","RedirectPath","RedirectTo","Target","FolderPath"
        )
        if (-not $Target) {
            $Target = Get-XmlPropertyValue $Redirect @(
                "Path","TargetPath","DestinationPath","RedirectPath","RedirectTo","Target","FolderPath"
            )
        }
        if (-not $Target -and $Redirect.Location) {
            $Target = Get-XmlPropertyValue $Redirect.Location @("DestinationPath","Path","TargetPath")
        }

        $FollowParent = Get-XmlPropertyValue $Redirect.Properties @("FollowParent","FollowFolder","FollowDocuments")
        if (-not $FollowParent) {
            $FollowParent = Get-XmlPropertyValue $Redirect @("FollowParent","FollowFolder","FollowDocuments")
        }

        $FolderDisplay = $FolderName
        if ($FollowParent -match '^(?i:true|1)$') {
            if ($Target -and $Target -notmatch '[\\/]') {
                $FolderDisplay = $Target
                $Target = "(follow parent)"
            } elseif (-not $Target -or $Target -eq $FolderName) {
                $Target = "(follow parent)"
            }
        } elseif ((-not $FolderDisplay -or $FolderDisplay -eq "Folder") -and $Target -match '[\\/]') {
            $FolderDisplay = Split-Path -Path $Target -Leaf
        }

        $Mode = Get-XmlPropertyValue $Redirect.Properties @("PolicyRemovalBehavior","PolicyRemoval","RemovalPolicy","Action","Policy")
        if (-not $Mode) {
            $Mode = Get-XmlPropertyValue $Redirect @("PolicyRemovalBehavior","PolicyRemoval","RemovalPolicy","Action","Policy")
        }

        $script:FolderRedirections += [pscustomobject]@{
            GPO       = $GpoName
            LinkCount = $LinkCount
            Enabled   = $Enabled
            Folder    = $FolderDisplay
            Target    = $Target
            FollowParent = $FollowParent
            Mode      = $Mode
        }
    }
}

function Add-RoamingProfiles {
    param($GpoName, $LinkCount, $Enabled, $Extension)
    # Some profiles are stored under an extension named "User" or "User Profiles"
    $ProfilePath = $Extension.Extension
    if (-not $ProfilePath) { return }
    $ProfilePath = $ProfilePath.Path
    if ($ProfilePath) {
        $script:RoamingProfiles += [pscustomobject]@{
            GPO       = $GpoName
            LinkCount = $LinkCount
            Enabled   = $Enabled
            Profile   = $ProfilePath
        }
    }
}

function Add-SectionOutput {
    param(
        [string]$Title,
        [array]$Data,
        [string[]]$Columns,
        [string]$EmptyMessage
    )

    if (-not $Data -or $Data.Count -eq 0) {
        $script:OutputBlocks += "$Title`n  $EmptyMessage"
        return
    }

    $table = $Data | Format-Table $Columns -AutoSize | Out-String -Width 200
    $script:OutputBlocks += "$Title`n$table"
}

foreach ($Report in $Reports) {
    $ReportXml = [xml]$Report
    $GPO = $ReportXml.GPO
    $LinkCount = ([string[]]$ReportXml.GPO.LinksTo).Count
    $UserEnabled = $GPO.User.Enabled
    $ComputerEnabled = $GPO.Computer.Enabled

    foreach ($ExtensionData in $GPO.User.ExtensionData) {
        switch ($ExtensionData.Name) {
            "Drive Maps" { Add-DriveMappings $GPO.Name $LinkCount $UserEnabled $ExtensionData }
            "Folder Redirection" { Add-FolderRedirects $GPO.Name $LinkCount $UserEnabled $ExtensionData }
            {$_ -in @("User", "User Profiles")} { Add-RoamingProfiles $GPO.Name $LinkCount $UserEnabled $ExtensionData }
        }
    }

    foreach ($ExtensionData in $GPO.Computer.ExtensionData) {
        switch ($ExtensionData.Name) {
            "Drive Maps" { Add-DriveMappings $GPO.Name $LinkCount $ComputerEnabled $ExtensionData }
            "Folder Redirection" { Add-FolderRedirects $GPO.Name $LinkCount $ComputerEnabled $ExtensionData }
            {$_ -in @("User", "User Profiles")} { Add-RoamingProfiles $GPO.Name $LinkCount $ComputerEnabled $ExtensionData }
        }
    }
}

$DocumentTargetsByGpo = @{}
foreach ($Item in $FolderRedirections) {
    if ($DocumentTargetsByGpo.ContainsKey($Item.GPO)) { continue }
    $IsDocumentsFolder = $Item.Folder -match '^(?i:My\s+Documents|Documents)$'
    $IsDocumentsTarget = $Item.Target -match '(?i:\\(My Documents|Documents))$'
    if (($IsDocumentsFolder -or $IsDocumentsTarget) -and $Item.Target -and $Item.Target -ne "(follow parent)") {
        $DocumentTargetsByGpo[$Item.GPO] = $Item.Target
    }
}

foreach ($Item in $FolderRedirections) {
    $IsFollowParent = $Item.FollowParent -match '^(?i:true|1)$'
    if ($IsFollowParent -and $DocumentTargetsByGpo.ContainsKey($Item.GPO)) {
        $Item.Target = $DocumentTargetsByGpo[$Item.GPO]
    }
}

Add-SectionOutput -Title "Mapped Drives" -Data $DriveMappings -Columns @("GPO","LinkCount","Enabled","DriveLetter","Label","Path") -EmptyMessage "No drive mappings found in any GPO."
Add-SectionOutput -Title "Folder Redirection" -Data $FolderRedirections -Columns @("GPO","LinkCount","Enabled","Folder","Target","FollowParent","Mode") -EmptyMessage "No folder redirection settings found in any GPO."
Add-SectionOutput -Title "Roaming Profiles" -Data $RoamingProfiles -Columns @("GPO","LinkCount","Enabled","Profile") -EmptyMessage "No roaming profile paths found in any GPO."

$OutputBlocks -join "`n" | Write-Output
