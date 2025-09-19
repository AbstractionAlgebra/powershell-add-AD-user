# PowerShell AD User Management with Linux Attributes

A comprehensive PowerShell script for creating Active Directory users with Linux POSIX attributes on Windows Server 2019 1809 Domain Controllers. Designed for environments with AD-joined Ubuntu and RHEL systems requiring seamless user authentication.

## Features

- **Windows Server 2019 1809 Validated**: Tested and optimized for Windows Server 2019 1809 (Build 17763)
- **Linux Integration**: Full POSIX attribute support (uidNumber, gidNumber, loginShell, unixHomeDirectory)
- **Flexible UID Management**: Sequential, auto-discovery, or employee ID-based UID assignment
- **Batch Processing**: Single user or CSV file batch creation
- **Group Management**: Multiple group assignment with validation
- **Security**: Secure password generation and comprehensive validation
- **Error Handling**: Robust error handling with detailed logging

## Requirements

### System Requirements
- Windows Server 2019 1809 (Build 17763) or later
- Active Directory Domain Services role installed
- PowerShell 5.1 or later
- Active Directory PowerShell module (RSAT-AD-PowerShell)

### Permissions Required
- Domain Administrator privileges (or delegated permissions for user creation)
- Read/Write access to Active Directory
- Permission to modify POSIX attributes

### AD Schema Requirements
Your Active Directory schema must support POSIX attributes. These are typically available by default in Windows Server 2019, but verify the following attributes exist:
- `uidNumber`
- `gidNumber`
- `loginShell`
- `unixHomeDirectory`

## Installation

1. Clone or download the repository:
   ```powershell
   git clone https://github.com/AbstractionAlgebra/powershell-add-AD-user.git
   cd powershell-add-AD-user
   ```

2. Verify Active Directory module is available:
   ```powershell
   Get-Module -Name ActiveDirectory -ListAvailable
   ```

3. If AD module is not available, install RSAT tools:
   ```powershell
   Install-WindowsFeature -Name RSAT-AD-PowerShell
   ```

4. Review and customize the configuration file:
   ```powershell
   notepad ADUserConfig.psd1
   ```

## Configuration

Edit `ADUserConfig.psd1` to match your environment:

```powershell
@{
    DefaultOU = "CN=Users"          # Default OU for new users
    UIDMin = 10000                  # Minimum UID for Linux users
    UIDMax = 65000                  # Maximum UID for Linux users
    GIDDefault = 10000              # Default GID (typically 'users' group)
    LoginShell = "/bin/bash"        # Default shell for Linux users
    HomeDirectoryBase = "/home"     # Base path for home directories
}
```

## Usage

### Single User Creation

Create a user with sequential UID assignment:
```powershell
.\Add-ADUserWithLinuxAttributes.ps1 `
    -UserName "jdoe" `
    -FirstName "John" `
    -LastName "Doe" `
    -EmailAddress "jdoe@company.com" `
    -Groups @("Domain Users", "LinuxUsers") `
    -UIDMode "Sequential"
```

Create a user using employee ID as UID:
```powershell
.\Add-ADUserWithLinuxAttributes.ps1 `
    -UserName "jsmith" `
    -FirstName "Jane" `
    -LastName "Smith" `
    -EmailAddress "jsmith@company.com" `
    -EmployeeID "12345" `
    -UIDMode "EmployeeID" `
    -Groups @("Domain Users", "Administrators")
```

Create a user with specific UID:
```powershell
.\Add-ADUserWithLinuxAttributes.ps1 `
    -UserName "bwilson" `
    -FirstName "Bob" `
    -LastName "Wilson" `
    -EmailAddress "bwilson@company.com" `
    -SpecificUID 15000 `
    -Groups @("Domain Users")
```

### Batch User Creation

Use the provided CSV template (`users-template.csv`) as a starting point:

```csv
UserName,FirstName,LastName,EmailAddress,EmployeeID,Groups,UIDMode,SpecificUID,Department
jdoe,John,Doe,jdoe@company.com,12345,Domain Users;LinuxUsers,Sequential,,IT
jsmith,Jane,Smith,jsmith@company.com,12346,Domain Users;Administrators,EmployeeID,,IT
```

Run batch creation:
```powershell
.\Add-ADUserWithLinuxAttributes.ps1 -CSVFile "C:\Path\To\users.csv"
```

### Testing Mode

Use `-WhatIf` to preview changes without creating users:
```powershell
.\Add-ADUserWithLinuxAttributes.ps1 `
    -UserName "testuser" `
    -FirstName "Test" `
    -LastName "User" `
    -WhatIf
```

## UID Management Modes

### Sequential Mode
Finds the highest existing UID and increments by 1:
```powershell
-UIDMode "Sequential"
```

### Auto Mode
Finds the next available UID in the specified range:
```powershell
-UIDMode "Auto"
```

### EmployeeID Mode
Uses the employee ID as the UID (validates range and uniqueness):
```powershell
-UIDMode "EmployeeID" -EmployeeID "12345"
```

### Specific UID
Override all modes with a specific UID:
```powershell
-SpecificUID 15000
```

## CSV File Format

The CSV file must contain the following required columns:
- `UserName`: AD username (SamAccountName)
- `FirstName`: User's first name
- `LastName`: User's last name

Optional columns:
- `EmailAddress`: Email address
- `EmployeeID`: Employee ID number
- `Groups`: Semicolon-separated list of groups
- `UIDMode`: Sequential, Auto, or EmployeeID
- `SpecificUID`: Override UID (leave blank to use UIDMode)
- `Department`: For organizational purposes

## Windows Server 2019 1809 Compatibility

This script has been specifically validated for Windows Server 2019 1809:

### Verified Components
- Active Directory PowerShell module version compatibility
- POSIX attribute schema support
- Group membership cmdlets
- Security and permissions model

### Known Compatible Builds
- 17763 (Windows Server 2019 1809) - Primary target
- 17784+ (Windows Server 2019 updates)
- 19041+ (Windows Server 2019 20H1+)
- 20348+ (Windows Server 2022)

### Version Checking
The script automatically validates the Windows Server version and warns if running on unsupported builds:

```powershell
# Automatic version validation
$OSVersion = Get-CimInstance -ClassName Win32_OperatingSystem
if ($OSVersion.BuildNumber -lt 17763) {
    Write-Warning "This script is optimized for Windows Server 2019 1809 or later"
}
```

## Linux Integration

### POSIX Attributes Set
For each user, the following POSIX attributes are configured:
- `uidNumber`: Unique Linux user ID
- `gidNumber`: Linux group ID (configurable, default 10000)
- `loginShell`: Default shell (configurable, default `/bin/bash`)
- `unixHomeDirectory`: Home directory path (`/home/username`)

### AD-Joined Linux Systems
These attributes enable seamless authentication on:
- Ubuntu systems joined to AD
- RHEL/CentOS systems joined to AD
- Any Linux system using SSSD or similar AD integration

### Example Linux Configuration
On Ubuntu systems with `realmd` and `sssd`:
```bash
# /etc/sssd/sssd.conf
[domain/your-domain.com]
ldap_id_mapping = false
ldap_user_uid_number = uidNumber
ldap_user_gid_number = gidNumber
ldap_user_shell = loginShell
ldap_user_home_directory = unixHomeDirectory
```

## Security Considerations

### Password Security
- Generates cryptographically secure random passwords
- Default 12-character length with mixed character sets
- Passwords are displayed once and not logged
- Users are required to change password on first login

### Permissions
- Validates AD connectivity before execution
- Checks user creation permissions
- Validates group membership permissions
- Implements principle of least privilege

### Audit Trail
- Comprehensive logging of all operations
- User creation timestamps and details
- Error logging for failed operations
- No sensitive information (passwords) logged

## Troubleshooting

### Common Issues

**"Active Directory module not found"**
```powershell
# Install RSAT tools
Install-WindowsFeature -Name RSAT-AD-PowerShell
```

**"No available UIDs in range"**
- Increase UID range in `ADUserConfig.psd1`
- Clean up unused user accounts
- Use specific UID assignment

**"User already exists"**
- Check for duplicate usernames
- Verify user wasn't previously created
- Use different username

**"Permission denied"**
- Ensure running as Domain Administrator
- Verify AD connectivity
- Check OU permissions

### Verbose Logging
Enable verbose output for troubleshooting:
```powershell
.\Add-ADUserWithLinuxAttributes.ps1 -UserName "test" -FirstName "Test" -LastName "User" -Verbose
```

### Log Files
Check the log file for detailed operation history:
```powershell
Get-Content ADUserCreation.log | Select-Object -Last 50
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Test on Windows Server 2019 1809
4. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Support

For issues and support:
- GitHub Issues: https://github.com/AbstractionAlgebra/powershell-add-AD-user/issues
- Documentation: This README and inline PowerShell help

## Changelog

### Version 1.0
- Initial release
- Windows Server 2019 1809 compatibility
- POSIX attribute support
- Flexible UID management
- CSV batch processing
- Comprehensive error handling