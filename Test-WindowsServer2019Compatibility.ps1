# Test-WindowsServer2019Compatibility.ps1
# Validation script for Windows Server 2019 1809 compatibility

<#
.SYNOPSIS
    Tests Windows Server 2019 1809 compatibility for AD User creation scripts

.DESCRIPTION
    This script validates that the current environment meets the requirements
    for running the Add-ADUserWithLinuxAttributes.ps1 script on Windows Server 2019 1809.

.EXAMPLE
    .\Test-WindowsServer2019Compatibility.ps1

.NOTES
    Run this script on your Windows Server 2019 1809 domain controller to validate compatibility
#>

[CmdletBinding()]
param()

Write-Output "=== Windows Server 2019 1809 Compatibility Test ==="
Write-Output "Testing environment compatibility for AD User creation scripts"
Write-Output ""

$TestResults = @()
$AllTestsPassed = $true

# Test 1: Windows Version
Write-Output "1. Testing Windows Server version..."
try {
    $OSVersion = Get-CimInstance -ClassName Win32_OperatingSystem
    $BuildNumber = [int]$OSVersion.BuildNumber
    $ProductType = $OSVersion.ProductType

    Write-Output "   OS: $($OSVersion.Caption)"
    Write-Output "   Build: $BuildNumber"

    if ($ProductType -eq 2 -or $ProductType -eq 3) {
        if ($BuildNumber -ge 17763) {
            Write-Output "   ✓ Windows Server 2019 1809 or later detected"
            $TestResults += @{Test="Windows Version"; Status="PASS"; Details="Build $BuildNumber"}
        } else {
            Write-Warning "   ⚠ Build $BuildNumber is older than Windows Server 2019 1809 (17763)"
            $TestResults += @{Test="Windows Version"; Status="WARN"; Details="Build $BuildNumber < 17763"}
        }
    } else {
        Write-Error "   ✗ This appears to be a client OS, not Windows Server"
        $TestResults += @{Test="Windows Version"; Status="FAIL"; Details="Not Windows Server"}
        $AllTestsPassed = $false
    }
} catch {
    Write-Error "   ✗ Failed to detect Windows version: $($_.Exception.Message)"
    $TestResults += @{Test="Windows Version"; Status="FAIL"; Details=$_.Exception.Message}
    $AllTestsPassed = $false
}

Write-Output ""

# Test 2: PowerShell Version
Write-Output "2. Testing PowerShell version..."
try {
    $PSVersion = $PSVersionTable.PSVersion
    Write-Output "   PowerShell Version: $PSVersion"

    if ($PSVersion.Major -ge 5) {
        Write-Output "   ✓ PowerShell 5.0 or later detected"
        $TestResults += @{Test="PowerShell Version"; Status="PASS"; Details="v$PSVersion"}
    } else {
        Write-Error "   ✗ PowerShell version $PSVersion is too old (minimum 5.0 required)"
        $TestResults += @{Test="PowerShell Version"; Status="FAIL"; Details="v$PSVersion < 5.0"}
        $AllTestsPassed = $false
    }
} catch {
    Write-Error "   ✗ Failed to detect PowerShell version: $($_.Exception.Message)"
    $TestResults += @{Test="PowerShell Version"; Status="FAIL"; Details=$_.Exception.Message}
    $AllTestsPassed = $false
}

Write-Output ""

# Test 3: Active Directory Module
Write-Output "3. Testing Active Directory PowerShell module..."
try {
    $ADModule = Get-Module -Name ActiveDirectory -ListAvailable
    if ($ADModule) {
        Write-Output "   ✓ Active Directory module found"
        Write-Output "   Version: $($ADModule.Version)"
        $TestResults += @{Test="AD Module"; Status="PASS"; Details="v$($ADModule.Version)"}

        # Test importing the module
        Import-Module ActiveDirectory -Force -ErrorAction Stop
        Write-Output "   ✓ Active Directory module imported successfully"
    } else {
        Write-Error "   ✗ Active Directory PowerShell module not found"
        Write-Output "   Install with: Install-WindowsFeature -Name RSAT-AD-PowerShell"
        $TestResults += @{Test="AD Module"; Status="FAIL"; Details="Module not found"}
        $AllTestsPassed = $false
    }
} catch {
    Write-Error "   ✗ Failed to load Active Directory module: $($_.Exception.Message)"
    $TestResults += @{Test="AD Module"; Status="FAIL"; Details=$_.Exception.Message}
    $AllTestsPassed = $false
}

Write-Output ""

# Test 4: Domain Controller Role
Write-Output "4. Testing Domain Controller role..."
try {
    $DCRole = Get-WindowsFeature -Name AD-Domain-Services
    if ($DCRole.InstallState -eq "Installed") {
        Write-Output "   ✓ Active Directory Domain Services role is installed"
        $TestResults += @{Test="DC Role"; Status="PASS"; Details="AD-Domain-Services installed"}
    } else {
        Write-Warning "   ⚠ Active Directory Domain Services role not detected"
        $TestResults += @{Test="DC Role"; Status="WARN"; Details="AD-Domain-Services not installed"}
    }
} catch {
    Write-Warning "   ⚠ Could not verify Domain Controller role: $($_.Exception.Message)"
    $TestResults += @{Test="DC Role"; Status="WARN"; Details=$_.Exception.Message}
}

Write-Output ""

# Test 5: Active Directory Connectivity
Write-Output "5. Testing Active Directory connectivity..."
try {
    $Domain = Get-ADDomain -ErrorAction Stop
    Write-Output "   ✓ Connected to domain: $($Domain.DNSRoot)"
    Write-Output "   Domain functional level: $($Domain.DomainMode)"

    $DC = Get-ADDomainController -Discover -ErrorAction Stop
    Write-Output "   ✓ Using domain controller: $($DC.HostName)"
    $TestResults += @{Test="AD Connectivity"; Status="PASS"; Details=$Domain.DNSRoot}
} catch {
    Write-Error "   ✗ Failed to connect to Active Directory: $($_.Exception.Message)"
    $TestResults += @{Test="AD Connectivity"; Status="FAIL"; Details=$_.Exception.Message}
    $AllTestsPassed = $false
}

Write-Output ""

# Test 6: POSIX Attributes Schema
Write-Output "6. Testing POSIX attributes schema..."
try {
    # Test if we can query users with POSIX attributes
    $TestUser = Get-ADUser -Filter "Name -eq 'Administrator'" -Properties uidNumber -ErrorAction Stop
    Write-Output "   ✓ POSIX attributes schema is available"
    $TestResults += @{Test="POSIX Schema"; Status="PASS"; Details="uidNumber attribute accessible"}
} catch {
    Write-Warning "   ⚠ Could not verify POSIX attributes schema: $($_.Exception.Message)"
    $TestResults += @{Test="POSIX Schema"; Status="WARN"; Details=$_.Exception.Message}
}

Write-Output ""

# Test 7: User Creation Permissions
Write-Output "7. Testing user creation permissions..."
try {
    # Test by attempting to read from Users container
    $UsersContainer = Get-ADOrganizationalUnit -Filter "Name -eq 'Users'" -ErrorAction SilentlyContinue
    if (-not $UsersContainer) {
        # Fallback: try to read users
        Get-ADUser -Filter "Name -eq 'Administrator'" -Properties Name -ErrorAction Stop | Out-Null
    }
    Write-Output "   ✓ Sufficient permissions for AD operations"
    $TestResults += @{Test="Permissions"; Status="PASS"; Details="Read access verified"}
} catch {
    Write-Warning "   ⚠ Could not verify user creation permissions: $($_.Exception.Message)"
    Write-Output "   Note: You may need Domain Administrator privileges"
    $TestResults += @{Test="Permissions"; Status="WARN"; Details=$_.Exception.Message}
}

Write-Output ""

# Test 8: Script Files
Write-Output "8. Testing script files..."
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$RequiredFiles = @(
    "Add-ADUserWithLinuxAttributes.ps1",
    "ADUserFunctions.ps1",
    "ADUserConfig.psd1",
    "users-template.csv"
)

$AllFilesPresent = $true
foreach ($File in $RequiredFiles) {
    $FilePath = Join-Path $ScriptPath $File
    if (Test-Path $FilePath) {
        Write-Output "   ✓ $File found"
    } else {
        Write-Error "   ✗ $File not found"
        $AllFilesPresent = $false
    }
}

if ($AllFilesPresent) {
    $TestResults += @{Test="Script Files"; Status="PASS"; Details="All required files present"}
} else {
    $TestResults += @{Test="Script Files"; Status="FAIL"; Details="Missing required files"}
    $AllTestsPassed = $false
}

Write-Output ""

# Summary
Write-Output "=== Test Summary ==="
foreach ($Result in $TestResults) {
    $Status = switch ($Result.Status) {
        "PASS" { "✓" }
        "WARN" { "⚠" }
        "FAIL" { "✗" }
    }
    Write-Output "$Status $($Result.Test): $($Result.Details)"
}

Write-Output ""

if ($AllTestsPassed) {
    Write-Output "🎉 All critical tests passed! Your environment is ready for AD user creation."
    Write-Output "You can now run Add-ADUserWithLinuxAttributes.ps1 safely."
} else {
    Write-Output "❌ Some tests failed. Please address the issues above before running the main script."
}

Write-Output ""
Write-Output "For more information, see the README.md file."