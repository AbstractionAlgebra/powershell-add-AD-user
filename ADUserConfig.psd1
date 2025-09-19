# ADUserConfig.psd1
# Configuration file for AD User creation with Linux attributes
# Windows Server 2019 1809 compatible settings

@{
    # Active Directory Settings
    DefaultOU = "CN=Users"  # Default Organizational Unit for new users

    # UID/GID Range Settings for Linux integration
    UIDMin = 10000          # Minimum UID for user accounts
    UIDMax = 65000          # Maximum UID for user accounts
    GIDDefault = 10000      # Default GID for all users (typically 'users' group)

    # Linux Environment Settings
    LoginShell = "/bin/bash"           # Default shell for Linux users
    HomeDirectoryBase = "/home"        # Base path for home directories

    # Default Groups
    DefaultGroups = @(
        "Domain Users"                 # Standard domain users group
        # "LinuxUsers"                 # Uncomment if you have a specific Linux users group
    )

    # Password Policy
    PasswordLength = 12                # Minimum password length for generated passwords
    RequirePasswordChange = $true      # Force password change on first login

    # Windows Server 2019 1809 Specific Settings
    SupportedOSVersions = @{
        MinimumBuild = 17763          # Windows Server 2019 1809 build number
        RecommendedBuild = 17763      # Recommended minimum build
        TestedBuilds = @(17763, 17784, 19041, 20348)  # Known working builds
    }

    # Schema Requirements
    RequiredAttributes = @(
        "uidNumber"                   # POSIX UID attribute
        "gidNumber"                   # POSIX GID attribute
        "loginShell"                  # POSIX login shell
        "unixHomeDirectory"           # POSIX home directory
    )

    # Logging Settings
    LoggingEnabled = $true
    LogFile = "ADUserCreation.log"
    LogLevel = "INFO"                 # Options: DEBUG, INFO, WARN, ERROR

    # Validation Settings
    ValidateUsername = $true          # Validate username format
    ValidateEmailFormat = $true       # Validate email address format
    CheckUIDConflicts = $true         # Check for UID conflicts before creation

    # Security Settings
    SecurePasswordGeneration = $true   # Use cryptographically secure password generation
    LogPasswords = $false             # NEVER log passwords (security best practice)

    # Performance Settings
    BatchSize = 50                    # Maximum users to process in a single batch
    DelayBetweenCreations = 100       # Milliseconds delay between user creations (helps with replication)

    # Error Handling
    ContinueOnError = $true           # Continue processing other users if one fails
    MaxRetries = 3                    # Maximum retries for failed operations

    # Integration Settings
    SambaIntegration = @{
        Enabled = $false              # Set to $true if using Samba integration
        SambaSchema = $false          # Set to $true if Samba schema extensions are installed
    }

    # Custom Organizational Units (modify as needed for your environment)
    OrganizationalUnits = @{
        IT = "OU=IT,CN=Users"
        Finance = "OU=Finance,CN=Users"
        HR = "OU=HR,CN=Users"
        Sales = "OU=Sales,CN=Users"
        Support = "OU=Support,CN=Users"
    }

    # Custom Group Mappings (modify as needed)
    DepartmentGroups = @{
        IT = @("Domain Users", "IT_Users", "LinuxAdmins")
        Finance = @("Domain Users", "Finance_Users")
        HR = @("Domain Users", "HR_Users")
        Sales = @("Domain Users", "Sales_Users")
        Support = @("Domain Users", "Support_Users")
    }
}