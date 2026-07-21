<#
Pseudo Home Folder Creation Script for Logon

Purpose:
- Automatically create a user-specific folder in a shared location when the user logs in.
- Ensure the user has Full Control over their own folder and all contents, while retaining inherited permissions for admins and other accounts.
- Emulates the behavior of a Windows home folder, but for a custom share.

Requirements:
- The root folder (e.g., \\Server0-1\Home) must have NTFS permissions:
    - "List folder", "Create folder", "Read permissions" for Domain Users or Authenticated Users. (Under advanced permissions)
- Place this script in SYSVOL and assign as a User Logon Script via Group Policy.

How it works:
- Checks if the user's folder exists; if not, creates it.
- Adds an explicit Full Control permission for the user, propagating to all files and subfolders.
- Does NOT break inheritance or remove any existing permissions.
#>
# CONFIGURE BEFORE DEPLOYMENT: Update this path to match the actual file server share for this environment before placing in SYSVOL.
$serverpath = "\\Server-01\Home"  # Root path for all user folders
$folderPath = "$serverpath\$env:USERNAME"  # Path to the user's Home folder
$user = "$env:USERDOMAIN\$env:USERNAME"          # Current user's username

# Check if the folder exists
if (!(Test-Path $folderPath)) {
    # Create the folder if it doesn't exist
    New-Item -ItemType Directory -Path $folderPath | Out-Null

    # Get the current ACL (permissions), which includes inherited permissions
    $acl = Get-Acl $folderPath

    # Create a new access rule: Full Control for the user, applies to all files/subfolders
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $user, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
    )

    # Add the new rule to the ACL (does not remove or change inherited permissions)
    $acl.AddAccessRule($accessRule)

    # Apply the updated ACL to the folder
    Set-Acl $folderPath $acl
}