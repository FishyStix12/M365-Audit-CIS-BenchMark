#################################################################################################
# Author: Nicholas Fisher
# Date: April 10 2025
# Description of Script
# M365UserandAdminSecTest.ps1 - audits Microsoft 365 user and administrator security 
# configurations. It collects details about global admins, privileged role assignments, and 
# user settings to assess risks such as excessive privileges or inactive high-privilege accounts. 
# Results are exported to CSV files for reporting and review, helping strengthen the overall 
# security posture of M365 environments.
#################################################################################################
# Set up a consistent output folder
$outputDirectory = Join-Path -Path $PSScriptRoot -ChildPath "Scripts-M365Assessment-Reports"

# Create the output folder if it doesn't exist
if (-not (Test-Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory | Out-Null
}

# --- Initialize and Import Modules
# We need to make sure that the necessary PowerShell modules (AzureAD and MSOnline) are installed
$moduleName = 'AzureAD'
$msolModuleName = 'MSOnline'

# Check if the AzureAD module is already installed; if not, install it
if (-not (Get-Module -ListAvailable -Name $moduleName)) {
    Write-Host "AzureAD module is not installed. Installing..."
    Install-Module -Name $moduleName -Force -Scope CurrentUser
}

# Check if the MSOnline module is already installed; if not, install it
if (-not (Get-Module -ListAvailable -Name $msolModuleName)) {
    Write-Host "MSOnline module is not installed. Installing..."
    Install-Module -Name $msolModuleName -Force -Scope CurrentUser
}

# Import the modules after installing them to enable their use
Write-Host "Importing the AzureAD and MSOnline modules..."
Import-Module $moduleName
Import-Module $msolModuleName

# Connect to Azure AD using the AzureAD module
Write-Host "Connecting to Azure AD..."
Connect-AzureAD

# Connect to MSOnline service for MFA checks (important for control 1.4)
Connect-MsolService

# --- Control 1.2: Global Admins (Scuba Style - Get All)
# Fetching all global administrator users from Azure AD
Write-Host "Fetching global admin users..."
$globalAdmins = @()  # Create an empty array to store global admin users
$roles = Get-AzureADDirectoryRole  # Get all the roles in the directory
foreach ($role in $roles) {
    # Check if the role is either 'Global Administrator' or 'Company Administrator'
    if ($role.DisplayName -eq "Global Administrator" -or $role.DisplayName -eq "Company Administrator") {
        # Fetch all the members for this role
        $roleMembers = Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId
        foreach ($member in $roleMembers) {
            # Ensure the user is a valid user account (not a group or service principal)
            if ($member.UserPrincipalName -match "@") {
                # Add the global admin user to the array with relevant details
                $globalAdmins += [PSCustomObject]@{
                    DisplayName       = $member.DisplayName  # Display name of the admin
                    UserPrincipalName = $member.UserPrincipalName  # User Principal Name (email)
                    RoleName          = $role.DisplayName  # The role name (Global Admin or Company Admin)
                }
            }
        }
    }
}

# Check if we found any global admins and export to CSV
if ($globalAdmins.Count -gt 0) {
    $globalAdmins | Export-Csv -Path "$outputDirectory\GlobalAdmins_1.2.csv" -NoTypeInformation -Encoding UTF8
    Write-Host "Exported global admins to GlobalAdmins_1.2.csv. Total: $($globalAdmins.Count)"
} else {
    # If no global admins were found, just write the headers to a CSV file
    Write-Warning "No global admins found."
    "DisplayName,UserPrincipalName,RoleName" | Out-File -FilePath "$outputDirectory\GlobalAdmins_1.2.csv" -Encoding utf8
}

# --- Control 1.3: Admins Without P1 or P2 Licenses (Admin-only check)
# Fetching admins who do not have P1/P2 licenses (such as Enterprise Premium licenses)
Write-Host "Fetching admins without P1/P2 licenses..."
$sku = Get-AzureADSubscribedSku  # Get all subscriptions in Azure AD
$p1SkuId = ($sku | Where-Object { $_.SkuPartNumber -eq "ENTERPRISEPREMIUM" }).SkuId  # Find the P1 SKU
$p2SkuId = ($sku | Where-Object { $_.SkuPartNumber -eq "ENTERPRISEPREMIUM2" }).SkuId  # Find the P2 SKU

$allRoles = Get-AzureADDirectoryRole  # Get all roles again for the check
$adminsWithoutLicenses = @()  # Create an empty array to store admins without licenses
foreach ($role in $allRoles) {
    # Check for specific admin roles: Global Admin, User Admin, Service Support Admin
    if ($role.DisplayName -eq "Global Administrator" -or $role.DisplayName -eq "User Administrator" -or $role.DisplayName -eq "Service Support Administrator" ) {
        # Get the members of each role
        $roleMembers = Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId
        foreach ($member in $roleMembers) {
            try {
                # Attempt to get the user's license details
                $licenses = Get-AzureADUserLicenseDetail -ObjectId $member.ObjectId
                # Check if the user does not have P1 or P2 licenses
                if (-not ($licenses.SkuId -contains $p1SkuId) -and -not ($licenses.SkuId -contains $p2SkuId)) {
                    # Add this admin to the list of admins without P1/P2 licenses
                    $adminsWithoutLicenses += [PSCustomObject]@{
                        DisplayName       = $member.DisplayName
                        UserPrincipalName = $member.UserPrincipalName
                        RoleName          = $role.DisplayName
                    }
                }
            } catch {
                # Ignore errors related to license fetching (some users might not have license details)
            }
        }
    }
}

# Export to CSV
$adminsWithoutLicenses | Export-Csv -Path "$outputDirectory\AdminsWithoutP1P2_1.3.csv" -NoTypeInformation -Encoding UTF8
Write-Host "Exported admins without P1/P2 licenses to AdminsWithoutP1P2_1.3.csv. Total: $($adminsWithoutLicenses.Count)"

# --- Control 1.4: Users Without MFA Enabled
# Fetching all users who do not have MFA enabled
Write-Host "Fetching users without MFA enabled..."
$usersWithoutMFA = @()  # Array to store users without MFA
$allMsolUsers = Get-MsolUser -All  # Get all MSOL users
foreach ($user in $allMsolUsers) {
    $mfaStatus = $user.StrongAuthenticationMethods  # Check if MFA is enabled for the user
    if ($mfaStatus.Count -eq 0) {
        # Add users who don't have MFA enabled to the array
        $usersWithoutMFA += $user
    }
}
$usersWithoutMFA | Select-Object DisplayName, UserPrincipalName | Export-Csv -Path "$outputDirectory\UsersWithoutMFA_1.4.csv" -NoTypeInformation -Encoding UTF8
Write-Host "Exported users without MFA to UsersWithoutMFA_1.4.csv. Total: $($usersWithoutMFA.Count)"

# --- Control 1.5: Non-Cloud-Only Privileged Admins (Scuba Style)
# Fetching all privileged non-cloud-only admins (admins with on-premises ImmutableId)
Write-Host "Fetching non-cloud-only privileged admins..."
$nonCloudAdmins = @()  # Array to store non-cloud-only privileged admins
$privRoles = Get-AzureADDirectoryRole  # Get all privileged roles
foreach ($role in $privRoles) {
    $roleMembers = Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId
    foreach ($member in $roleMembers) {
        # Ensure that we only process user accounts
        if ($member.UserPrincipalName -match "@") {
            if (-not [string]::IsNullOrEmpty($member.ImmutableId)) {
                # Add non-cloud-only admins to the list
                $nonCloudAdmins += [PSCustomObject]@{
                    DisplayName       = $member.DisplayName
                    UserPrincipalName = $member.UserPrincipalName
                    RoleName          = $role.DisplayName
                    ImmutableId       = $member.ImmutableId
                }
            }
        }
    }
}

# Export non-cloud-only privileged admins to CSV
if ($nonCloudAdmins.Count -gt 0) {
    $nonCloudAdmins | Export-Csv -Path "$outputDirectory\NonCloudOnlyAdmins.csv" -NoTypeInformation -Encoding UTF8
    Write-Host "Exported non-cloud-only privileged admins to NonCloudOnlyAdmins.csv. Total: $($nonCloudAdmins.Count)"
} else {
    # If no non-cloud-only admins were found, just create a file with headers
    "DisplayName,UserPrincipalName,RoleName,ImmutableId" | Out-File -FilePath "$outputDirectory\NonCloudOnlyAdmins.csv" -Encoding utf8
    Write-Host "No non-cloud-only privileged admin accounts were found. This meets the MS.AAD.7.3v1 control requirement."
}

# --- Cleanup
Write-Host "Cleaning up by removing the AzureAD and MSOnline modules..."
Remove-Module $moduleName
Remove-Module $msolModuleName

Write-Host "Data collection for grabbing all Non-cloud-only Admins, Admins without a P1 or P2 license, all users without MFA, and all global admins is complete."
