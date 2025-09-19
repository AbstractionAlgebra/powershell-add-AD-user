# ADUserFunctions.ps1
# Supporting functions for Add-ADUserWithLinuxAttributes.ps1
# Windows Server 2019 1809 compatible AD user management functions

function Test-ADConnectivity {
    <#
    .SYNOPSIS
        Tests Active Directory connectivity and permissions
    #>
    try {
        $Domain = Get-ADDomain
        $DomainController = Get-ADDomainController -Discover

        Write-Verbose "Connected to domain: $($Domain.DNSRoot)"
        Write-Verbose "Using domain controller: $($DomainController.HostName)"

        # Test permissions by attempting to read from Users container
        $UsersContainer = Get-ADOrganizationalUnit -Filter "Name -eq 'Users'" -ErrorAction SilentlyContinue
        if (-not $UsersContainer) {
            Get-ADUser -Filter "Name -eq 'Administrator'" -Properties Name | Out-Null
        }

        return $true
    } catch {
        throw "AD connectivity test failed: $($_.Exception.Message)"
    }
}

function Get-NextSequentialUID {
    <#
    .SYNOPSIS
        Gets the next sequential UID by finding the highest existing UID and incrementing
    #>
    param(
        [int]$MinUID = 10000,
        [int]$MaxUID = 65000
    )

    try {
        # Get all users with uidNumber attribute
        $ExistingUIDs = Get-ADUser -Filter * -Properties uidNumber |
            Where-Object { $_.uidNumber -and $_.uidNumber -ge $MinUID -and $_.uidNumber -le $MaxUID } |
            Select-Object -ExpandProperty uidNumber |
            Sort-Object -Descending

        if ($ExistingUIDs) {
            $NextUID = $ExistingUIDs[0] + 1
        } else {
            $NextUID = $MinUID
        }

        if ($NextUID -gt $MaxUID) {
            throw "No available UIDs in range $MinUID-$MaxUID"
        }

        Write-Verbose "Next sequential UID: $NextUID"
        return $NextUID
    } catch {
        throw "Failed to get next sequential UID: $($_.Exception.Message)"
    }
}

function Get-NextAvailableUID {
    <#
    .SYNOPSIS
        Finds the next available UID in the specified range
    #>
    param(
        [int]$MinUID = 10000,
        [int]$MaxUID = 65000
    )

    try {
        # Get all existing UIDs in range
        $ExistingUIDs = Get-ADUser -Filter * -Properties uidNumber |
            Where-Object { $_.uidNumber -and $_.uidNumber -ge $MinUID -and $_.uidNumber -le $MaxUID } |
            Select-Object -ExpandProperty uidNumber |
            Sort-Object

        # Find first gap in sequence
        for ($uid = $MinUID; $uid -le $MaxUID; $uid++) {
            if ($uid -notin $ExistingUIDs) {
                Write-Verbose "Next available UID: $uid"
                return $uid
            }
        }

        throw "No available UIDs in range $MinUID-$MaxUID"
    } catch {
        throw "Failed to get next available UID: $($_.Exception.Message)"
    }
}

function Get-UIDFromEmployeeID {
    <#
    .SYNOPSIS
        Validates and returns employee ID as UID
    #>
    param(
        [string]$EmployeeID,
        [int]$MinUID = 10000,
        [int]$MaxUID = 65000
    )

    if (-not $EmployeeID) {
        throw "Employee ID is required when using EmployeeID UID mode"
    }

    # Convert to integer
    try {
        $UID = [int]$EmployeeID
    } catch {
        throw "Employee ID '$EmployeeID' is not a valid number"
    }

    # Validate range
    if ($UID -lt $MinUID -or $UID -gt $MaxUID) {
        throw "Employee ID $UID is outside allowed UID range ($MinUID-$MaxUID)"
    }

    # Check if UID is already in use
    $ExistingUser = Get-ADUser -Filter "uidNumber -eq $UID" -Properties uidNumber -ErrorAction SilentlyContinue
    if ($ExistingUser) {
        throw "UID $UID (Employee ID: $EmployeeID) is already in use by user: $($ExistingUser.SamAccountName)"
    }

    Write-Verbose "Using Employee ID as UID: $UID"
    return $UID
}

function New-ADUserWithLinuxAttributes {
    <#
    .SYNOPSIS
        Creates a new AD user with Linux POSIX attributes
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$UserName,

        [Parameter(Mandatory=$true)]
        [string]$FirstName,

        [Parameter(Mandatory=$true)]
        [string]$LastName,

        [string]$EmailAddress,
        [string]$EmployeeID,
        [string[]]$Groups = @("Domain Users"),
        [string]$UIDMode = 'Sequential',
        [int]$SpecificUID,
        [string]$OU,
        [int]$GID = 10000,
        [string]$LoginShell = "/bin/bash",
        [string]$HomeDirectoryBase = "/home"
    )

    try {
        # Validate user doesn't already exist
        if (Get-ADUser -Filter "SamAccountName -eq '$UserName'" -ErrorAction SilentlyContinue) {
            throw "User '$UserName' already exists"
        }

        # Determine UID
        if ($SpecificUID) {
            $UID = $SpecificUID
            # Validate specific UID isn't in use
            $ExistingUser = Get-ADUser -Filter "uidNumber -eq $UID" -Properties uidNumber -ErrorAction SilentlyContinue
            if ($ExistingUser) {
                throw "UID $UID is already in use by user: $($ExistingUser.SamAccountName)"
            }
        } else {
            switch ($UIDMode) {
                'Sequential' { $UID = Get-NextSequentialUID -MinUID $Config.UIDMin -MaxUID $Config.UIDMax }
                'Auto' { $UID = Get-NextAvailableUID -MinUID $Config.UIDMin -MaxUID $Config.UIDMax }
                'EmployeeID' { $UID = Get-UIDFromEmployeeID -EmployeeID $EmployeeID -MinUID $Config.UIDMin -MaxUID $Config.UIDMax }
                default { throw "Invalid UID mode: $UIDMode" }
            }
        }

        # Set default OU if not specified
        if (-not $OU) {
            $Domain = Get-ADDomain
            $OU = $Config.DefaultOU + "," + $Domain.DistinguishedName
        }

        # Generate secure random password
        $Password = New-RandomPassword
        $SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force

        # Prepare user attributes
        $UserAttributes = @{
            SamAccountName = $UserName
            UserPrincipalName = if ($EmailAddress) { $EmailAddress } else { "$UserName@$((Get-ADDomain).DNSRoot)" }
            Name = "$FirstName $LastName"
            GivenName = $FirstName
            Surname = $LastName
            DisplayName = "$FirstName $LastName"
            EmailAddress = $EmailAddress
            EmployeeID = $EmployeeID
            AccountPassword = $SecurePassword
            Enabled = $true
            Path = $OU
            OtherAttributes = @{
                uidNumber = $UID
                gidNumber = $GID
                loginShell = $LoginShell
                unixHomeDirectory = "$HomeDirectoryBase/$UserName"
            }
        }

        # Remove empty attributes
        $UserAttributes = $UserAttributes.GetEnumerator() | Where-Object { $_.Value } | ForEach-Object { @{$_.Key = $_.Value} }
        $FinalAttributes = @{}
        $UserAttributes | ForEach-Object { $FinalAttributes += $_ }

        Write-Output "Creating user: $UserName (UID: $UID)"

        # Create the user
        New-ADUser @FinalAttributes

        # Add to groups
        if ($Groups) {
            Add-UserToGroups -UserName $UserName -Groups $Groups
        }

        Write-Output "User '$UserName' created successfully with UID $UID"
        Write-Output "Temporary password: $Password"
        Write-Warning "Please provide the temporary password to the user and require them to change it on first login"

        return @{
            UserName = $UserName
            UID = $UID
            GID = $GID
            Password = $Password
            Success = $true
        }

    } catch {
        Write-Error "Failed to create user '$UserName': $($_.Exception.Message)"
        throw
    }
}

function Add-UserToGroups {
    <#
    .SYNOPSIS
        Adds a user to specified AD groups
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$UserName,

        [Parameter(Mandatory=$true)]
        [string[]]$Groups
    )

    foreach ($Group in $Groups) {
        try {
            # Verify group exists
            $ADGroup = Get-ADGroup -Filter "Name -eq '$Group'" -ErrorAction Stop

            # Add user to group
            Add-ADGroupMember -Identity $ADGroup -Members $UserName -ErrorAction Stop
            Write-Verbose "Added user '$UserName' to group '$Group'"

        } catch {
            Write-Warning "Failed to add user '$UserName' to group '$Group': $($_.Exception.Message)"
        }
    }
}

function New-RandomPassword {
    <#
    .SYNOPSIS
        Generates a secure random password
    #>
    param(
        [int]$Length = 12
    )

    $Characters = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%&*"
    $Password = ""

    for ($i = 0; $i -lt $Length; $i++) {
        $Password += $Characters[(Get-Random -Minimum 0 -Maximum $Characters.Length)]
    }

    return $Password
}

function Import-UsersFromCSV {
    <#
    .SYNOPSIS
        Imports and validates users from CSV file
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )

    try {
        if (-not (Test-Path $FilePath)) {
            throw "CSV file not found: $FilePath"
        }

        $Users = Import-Csv -Path $FilePath

        # Validate required columns
        $RequiredColumns = @('UserName', 'FirstName', 'LastName')
        $CSVColumns = $Users[0].PSObject.Properties.Name

        foreach ($Column in $RequiredColumns) {
            if ($Column -notin $CSVColumns) {
                throw "Required column '$Column' not found in CSV file"
            }
        }

        # Validate each user record
        foreach ($User in $Users) {
            if (-not $User.UserName -or -not $User.FirstName -or -not $User.LastName) {
                throw "Invalid user record found: UserName, FirstName, and LastName are required"
            }

            # Validate UserName format
            if ($User.UserName -notmatch '^[a-zA-Z0-9._-]+$') {
                throw "Invalid username format: $($User.UserName). Only letters, numbers, dots, hyphens, and underscores are allowed"
            }
        }

        Write-Output "Successfully validated $($Users.Count) users from CSV file"
        return $Users

    } catch {
        throw "CSV import failed: $($_.Exception.Message)"
    }
}

function Write-LogEntry {
    <#
    .SYNOPSIS
        Writes log entry with timestamp
    #>
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [string]$LogFile = "ADUserCreation.log"
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "$Timestamp [$Level] $Message"

    Write-Output $LogEntry

    try {
        Add-Content -Path $LogFile -Value $LogEntry -ErrorAction SilentlyContinue
    } catch {
        # Silently fail if can't write to log file
    }
}

# Export functions for use by main script
Export-ModuleMember -Function @(
    'Test-ADConnectivity',
    'Get-NextSequentialUID',
    'Get-NextAvailableUID',
    'Get-UIDFromEmployeeID',
    'New-ADUserWithLinuxAttributes',
    'Add-UserToGroups',
    'New-RandomPassword',
    'Import-UsersFromCSV',
    'Write-LogEntry'
)