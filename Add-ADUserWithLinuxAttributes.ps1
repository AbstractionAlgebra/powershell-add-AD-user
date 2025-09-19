<#
.SYNOPSIS
    Adds users to Windows Server 2019 1809 Active Directory with Linux UID/GUID attributes for AD-joined systems.

.DESCRIPTION
    This script creates Active Directory users with Linux POSIX attributes (uidNumber, gidNumber)
    for seamless integration with AD-joined Ubuntu and RHEL systems. Supports single user creation
    or batch processing via CSV file. Includes flexible UID management options and group membership assignment.

    Validated for Windows Server 2019 1809 Domain Controllers with Active Directory Domain Services.

.PARAMETER UserName
    The username for the new AD user (SamAccountName)

.PARAMETER FirstName
    The user's first name

.PARAMETER LastName
    The user's last name

.PARAMETER EmailAddress
    The user's email address

.PARAMETER EmployeeID
    The employee ID number (can be used as UID if -UseEmployeeIDAsUID is specified)

.PARAMETER Groups
    Array of AD groups to add the user to

.PARAMETER UIDMode
    UID assignment mode: 'Sequential' (auto-increment), 'Auto' (find next available), or 'EmployeeID'

.PARAMETER SpecificUID
    Specify a custom UID number (overrides UIDMode)

.PARAMETER CSVFile
    Path to CSV file for batch user creation

.PARAMETER WhatIf
    Shows what would be done without actually creating users

.EXAMPLE
    .\Add-ADUserWithLinuxAttributes.ps1 -UserName "jdoe" -FirstName "John" -LastName "Doe" -EmailAddress "jdoe@company.com" -Groups @("Domain Users", "LinuxUsers") -UIDMode "Sequential"

    Creates a single user with sequential UID assignment.

.EXAMPLE
    .\Add-ADUserWithLinuxAttributes.ps1 -UserName "jsmith" -FirstName "Jane" -LastName "Smith" -EmailAddress "jsmith@company.com" -EmployeeID "12345" -UIDMode "EmployeeID" -Groups @("Domain Users", "Administrators")

    Creates a user using employee ID as the UID.

.EXAMPLE
    .\Add-ADUserWithLinuxAttributes.ps1 -CSVFile "C:\Users\users.csv"

    Batch creates users from CSV file.

.NOTES
    Author: PowerShell AD User Management Script
    Version: 1.0
    Requirements:
    - Windows Server 2019 1809 or later
    - Active Directory PowerShell module
    - Domain Administrator privileges
    - AD Schema extended for POSIX attributes

.LINK
    https://github.com/AbstractionAlgebra/powershell-add-AD-user
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory=$false, ParameterSetName='SingleUser')]
    [string]$UserName,

    [Parameter(Mandatory=$false, ParameterSetName='SingleUser')]
    [string]$FirstName,

    [Parameter(Mandatory=$false, ParameterSetName='SingleUser')]
    [string]$LastName,

    [Parameter(Mandatory=$false, ParameterSetName='SingleUser')]
    [string]$EmailAddress,

    [Parameter(Mandatory=$false, ParameterSetName='SingleUser')]
    [string]$EmployeeID,

    [Parameter(Mandatory=$false, ParameterSetName='SingleUser')]
    [string[]]$Groups = @("Domain Users"),

    [Parameter(Mandatory=$false, ParameterSetName='SingleUser')]
    [ValidateSet('Sequential', 'Auto', 'EmployeeID')]
    [string]$UIDMode = 'Sequential',

    [Parameter(Mandatory=$false, ParameterSetName='SingleUser')]
    [int]$SpecificUID,

    [Parameter(Mandatory=$false, ParameterSetName='BatchUser')]
    [ValidateScript({Test-Path $_})]
    [string]$CSVFile,

    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

# Import required modules and functions
if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
    Write-Error "Active Directory PowerShell module is not available. Please install RSAT-AD-PowerShell feature."
    exit 1
}

Import-Module ActiveDirectory -Force

# Load configuration and supporting functions
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$ConfigPath = Join-Path $ScriptPath "ADUserConfig.psd1"
$FunctionsPath = Join-Path $ScriptPath "ADUserFunctions.ps1"

if (Test-Path $ConfigPath) {
    $Config = Import-PowerShellDataFile -Path $ConfigPath
} else {
    Write-Warning "Configuration file not found at $ConfigPath. Using default settings."
    $Config = @{
        DefaultOU = "CN=Users"
        UIDMin = 10000
        UIDMax = 65000
        GIDDefault = 10000
        LoginShell = "/bin/bash"
        HomeDirectoryBase = "/home"
    }
}

if (Test-Path $FunctionsPath) {
    . $FunctionsPath
} else {
    Write-Error "Required functions file not found at $FunctionsPath"
    exit 1
}

# Validate Windows Server 2019 1809 compatibility
try {
    $OSVersion = Get-CimInstance -ClassName Win32_OperatingSystem
    $BuildNumber = [int]$OSVersion.BuildNumber

    if ($BuildNumber -lt 17763) {
        Write-Warning "This script is optimized for Windows Server 2019 1809 (Build 17763) or later. Current build: $BuildNumber"
        Write-Warning "Some features may not work as expected on older versions."
    }

    Write-Verbose "Windows Server version validated: $($OSVersion.Caption) Build $BuildNumber"
} catch {
    Write-Warning "Could not verify Windows Server version: $($_.Exception.Message)"
}

# Validate AD connectivity and permissions
try {
    Test-ADConnectivity
    Write-Verbose "Active Directory connectivity verified"
} catch {
    Write-Error "Active Directory connectivity test failed: $($_.Exception.Message)"
    exit 1
}

# Main execution logic
try {
    if ($PSCmdlet.ParameterSetName -eq 'BatchUser') {
        # Process CSV file
        Write-Output "Processing users from CSV file: $CSVFile"
        $Users = Import-UsersFromCSV -FilePath $CSVFile

        foreach ($User in $Users) {
            $UserParams = @{
                UserName = $User.UserName
                FirstName = $User.FirstName
                LastName = $User.LastName
                EmailAddress = $User.EmailAddress
                EmployeeID = $User.EmployeeID
                Groups = if ($User.Groups) { $User.Groups -split ';' } else { @("Domain Users") }
                UIDMode = if ($User.UIDMode) { $User.UIDMode } else { 'Sequential' }
                SpecificUID = if ($User.SpecificUID) { [int]$User.SpecificUID } else { $null }
            }

            if ($WhatIf) {
                Write-Output "WHATIF: Would create user $($User.UserName)"
            } else {
                New-ADUserWithLinuxAttributes @UserParams
            }
        }
    } else {
        # Process single user
        if (-not $UserName -or -not $FirstName -or -not $LastName) {
            Write-Error "UserName, FirstName, and LastName are required for single user creation"
            exit 1
        }

        $UserParams = @{
            UserName = $UserName
            FirstName = $FirstName
            LastName = $LastName
            EmailAddress = $EmailAddress
            EmployeeID = $EmployeeID
            Groups = $Groups
            UIDMode = $UIDMode
            SpecificUID = $SpecificUID
        }

        if ($WhatIf) {
            Write-Output "WHATIF: Would create user $UserName"
        } else {
            New-ADUserWithLinuxAttributes @UserParams
        }
    }

    Write-Output "User creation process completed successfully"

} catch {
    Write-Error "An error occurred during user creation: $($_.Exception.Message)"
    Write-Error "Stack trace: $($_.ScriptStackTrace)"
    exit 1
}