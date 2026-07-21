<#
Requires PowerShell 7.2+ and the PnP.PowerShell module.

Before first use, register a PnP Entra app for the target tenant:
  Register-PnPEntraIDAppForInteractiveLogin -ApplicationName "PnP PowerShell" -SharePointDelegatePermissions "AllSites.FullControl" -Tenant <tenant>.onmicrosoft.com -Interactive

Usage:
  .\SharePoint-Download.ps1 -SourceSiteURL "https://<tenant>.sharepoint.com/sites/<site>" -ClientId "<App Registration ID>" [-LibraryName "Documents"] [-DownloadPath "C:\Site Downloads"]

Parameters:
  -SourceSiteURL   (Required) Full URL of the SharePoint site to download from.
  -ClientId        (Required) Entra app registration client ID with AllSites.FullControl.
  -LibraryName     Library to download. Defaults to "Documents". Pass "" to download all non-system libraries.
  -DownloadPath    Local folder for downloaded files. Defaults to "C:\Site Downloads".
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$SourceSiteURL,

    [Parameter(Mandatory = $true)]
    [string]$ClientId,

    [string]$LibraryName = "Documents",

    [string]$DownloadPath = "C:\Site Downloads"
)

#Function to Extract Metadata of a File to CSV File
Function Extract-PnPFileMetadata([Microsoft.SharePoint.Client.File]$SPFile)
{
    Try {
        #Calculate URLs
        $FileLibraryRelativeURL = $SPFile.ServerRelativeURL.Replace($global:Library.RootFolder.ServerRelativeURL,[string]::Empty)
        #Calculate Absolute URL
        If($global:Web.ServerRelativeUrl -eq "/")
        {
            $FileAbsoluteURL=  $("{0}{1}" -f $global:Web.Url, $SPFile.ServerRelativeUrl)
        }
        Else
        {
            $FileAbsoluteURL=  $("{0}{1}" -f $global:Web.Url.Replace($global:Web.ServerRelativeUrl,[string]::Empty), $SPFile.ServerRelativeUrl)
        }
        #Get Autor, Editor of the file 
        Get-PnPProperty -ClientObject $SPFile -Property Author, ModifiedBy
 
        #Extract the Metadata of the file
        $Metadata = New-Object PSObject 
        $Metadata | Add-Member -MemberType NoteProperty -name "FileName" -value $SPFile.Name
        $Metadata | Add-Member -MemberType NoteProperty -name "ParentLibrary" -value $global:Library.Title
        $Metadata | Add-Member -MemberType NoteProperty -name "FileAbsoluteURL" -value $FileAbsoluteURL
        $Metadata | Add-Member -MemberType NoteProperty -name "FileLibraryRelativeURL" -value $FileLibraryRelativeURL
        $Metadata | Add-Member -MemberType NoteProperty -Name "CreatedBy" -value $SPFile.Author.LoginName
        $Metadata | Add-Member -MemberType NoteProperty -name "ModifiedBy" -value $SPFile.ModifiedBy.LoginName
        $Metadata | Add-Member -MemberType NoteProperty -name "CreatedOn" -value $SPFile.TimeCreated 
        $Metadata | Add-Member -MemberType NoteProperty -name "ModifiedOn" -value $SPFile.TimeLastModified
  
        #Send the Metadata to CSV File
        $Metadata | Export-Csv $global:MetadataFile -NoTypeInformation -Append
        Write-host -f Green "`t`tMetadata Extracted from the File:"$SPFile.ServerRelativeURL
    }
    Catch {
        write-host -f Red "Error Getting Metadata:" $_.Exception.Message
    }
}
 
#Function to Download a Document Library from SharePoint Online site
Function Export-PnPLibrary()
{
    param
    (
        [Parameter(Mandatory=$true)] [string]$LibraryName
    )
 
    Try {
        Write-host "Exporting Library:"$LibraryName -f Yellow
 
        #Get the Library
        $global:Library = Get-PnPList -Identity $LibraryName -Includes RootFolder
 
        #Create a Local Folder for Document Library, if it doesn't exist
        $LocalFolder = $global:DownloadPath +"\" +$global:Library.RootFolder.Name
        If (!(Test-Path -Path $LocalFolder)) {
                New-Item -ItemType Directory -Path $LocalFolder | Out-Null
        }
        Write-host -f Yellow "`tEnsured Folder for Document Library '$LocalFolder'"
 
        #Get all Items from the Library - with progress bar
        $global:counter = 0
        $LibraryItems = Get-PnPListItem -List $LibraryName -PageSize 500 -Fields ID,FieldValues -ScriptBlock { Param($items) $global:counter += $items.Count; Write-Progress -PercentComplete `
                    ($global:Counter / ($global:Library.ItemCount) * 100) -Activity "Getting Items from Library:" -Status "Processing Items $global:Counter to $($global:Library.ItemCount)";} 
        Write-Progress -Activity "Completed Retrieving Folders from Library $LibraryName" -Completed
 
        #Get all Subfolders of the library
        $SubFolders = $LibraryItems | Where-Object {$_.FileSystemObjectType -eq "Folder" -and $_.FieldValues.FileLeafRef -ne "Forms"}
        $SubFolders | ForEach-Object {
            #Ensure All Folders in the Local Path
            $LocalFolder = $global:DownloadPath + ($_.FieldValues.FileRef.Substring($global:Web.ServerRelativeUrl.Length)) -replace "/","\"
            #Create Local Folder, if it doesn't exist
            If (!(Test-Path -Path $LocalFolder)) {
                    New-Item -ItemType Directory -Path $LocalFolder | Out-Null
            }
            Write-host -f Yellow "`tEnsured Folder '$LocalFolder'"
        }
 
        #Get all Files from the folder
        $FilesColl =  $LibraryItems | Where-Object {$_.FileSystemObjectType -eq "File"}
 
        $global:Filess = $FilesColl
        #Iterate through each file and download
        $FilesColl | ForEach-Object {
            Try {
                $FileDownloadPath = ($global:DownloadPath + ($_.FieldValues.FileRef.Substring($global:Web.ServerRelativeUrl.Length)) -replace "/","\").Replace($_.FieldValues.FileLeafRef,[string]::Empty)
                Get-PnPFile -Url $_.FieldValues.FileRef -Path $FileDownloadPath -FileName $_.FieldValues.FileLeafRef -AsFile -Force -ErrorAction Stop
                Write-host -f Green "`tDownloaded File from '$($_.FieldValues.FileRef)'"
                 
                #Get the Metadata of the File
                $File = Get-PnPProperty -ClientObject $_ -Property File
                Extract-PnPFileMetadata -SPFile $File
               }
            Catch {
                write-host -f Red "`tError Downloading File from '$($_.FieldValues.FileRef)' : "$_.Exception.Message
            }
        }
    }
    Catch {
        write-host -f Red "`tError:" $_.Exception.Message
    }
}
 
#Function to export all libraries in a SharePoint Site
Function Export-PnPLibraries()
{
    Try { 
        #Arry to Skip System Lists and Libraries
        $SystemLists =@("Converted Forms", "Master Page Gallery", "Customized Reports", "Form Templates", "List Template Gallery", "Theme Gallery",
               "Reporting Templates", "Solution Gallery", "Style Library", "Web Part Gallery","Site Assets", "wfpub", "Site Pages", "Images")
      
        #Filter Document Libraries to Scan 
        $LibraryCollection = Get-PnPList | Where-Object {$_.BaseType -eq "DocumentLibrary" -and $_.Hidden -eq $false -and $SystemLists -notcontains $_.Title -and $_.ItemCount -gt 0}
         
        #Loop through each document library
        ForEach($Library in $LibraryCollection)
        {
            #Call the function to download the document library
            Export-PnPLibrary -LibraryName $Library.Title
        }
    }
    Catch {
        Write-host -f Red "Error Downloading Libraries:" $_.Exception.Message
    }
}
 
#Connect to SharePoint Online
$global:DownloadPath = $DownloadPath
Connect-PnPOnline $SourceSiteURL -Interactive -ClientID $ClientId
$global:Web = Get-PnPWeb
$global:MetadataFile = "$global:DownloadPath\Metadata.csv"
 
#Delete any existing files and folders in the download location
If (Test-Path $global:DownloadPath) {Get-ChildItem -Path $global:DownloadPath -Recurse| ForEach-object {Remove-item -Recurse -path $_.FullName }}
 
#Call the function to download a library
Export-PnPLibrary -LibraryName $LibraryName
 
#To Export all libraries, use:
#Export-PnPLibraries