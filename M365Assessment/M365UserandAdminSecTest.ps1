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
if (-not (Test-Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory | Out-Null
}

# --- Initialize and Import Modules
$moduleName = 'AzureAD'
$msolModuleName = 'MSOnline'

if (-not (Get-Module -ListAvailable -Name $moduleName)) {
    Write-Host "AzureAD module is not installed. Installing..."
    Install-Module -Name $moduleName -Force -Scope CurrentUser
}
if (-not (Get-Module -ListAvailable -Name $msolModuleName)) {
    Write-Host "MSOnline module is not installed. Installing..."
    Install-Module -Name $msolModuleName -Force -Scope CurrentUser
}

Write-Host "Importing the AzureAD and MSOnline modules..."
Import-Module $moduleName
Import-Module $msolModuleName

Write-Host "Connecting to Azure AD..."
Connect-AzureAD | Out-Null
Connect-MsolService | Out-Null

# --- Control 1.2: Global Admins (Dynamic Role Detection)
Write-Host "Fetching global admin users..."
$globalAdmins = @()
$roles = Get-AzureADDirectoryRole | Where-Object { $_.DisplayName -match "Global Administrator|Company Administrator" }
foreach ($role in $roles) {
    $roleMembers = Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId
    foreach ($member in $roleMembers) {
        if ($member.ObjectType -eq "User") {
            $globalAdmins += [PSCustomObject]@{
                DisplayName       = $member.DisplayName
                UserPrincipalName = $member.UserPrincipalName
                RoleName          = $role.DisplayName
            }
        }
    }
}
if ($globalAdmins.Count -gt 0) {
    $globalAdmins | Export-Csv -Path "$outputDirectory\GlobalAdmins_1.2.csv" -NoTypeInformation -Encoding UTF8
    Write-Host "Exported global admins to GlobalAdmins_1.2.csv. Total: $($globalAdmins.Count)"
} else {
    Write-Warning "No global admins found."
    "DisplayName,UserPrincipalName,RoleName" | Out-File -FilePath "$outputDirectory\GlobalAdmins_1.2.csv" -Encoding utf8
}

# --- Control 1.3: Admins Without P1 or P2 Licenses
Write-Host "Fetching admins without P1/P2 licenses..."
$sku = Get-AzureADSubscribedSku
$p1SkuId = ($sku | Where-Object { $_.SkuPartNumber -eq "ENTERPRISEPREMIUM" }).SkuId
$p2SkuId = ($sku | Where-Object { $_.SkuPartNumber -eq "ENTERPRISEPREMIUM2" }).SkuId

$adminRoles = Get-AzureADDirectoryRole | Where-Object { $_.DisplayName -match "Admin|Administrator" }
$adminsWithoutLicenses = @()

foreach ($role in $adminRoles) {
    $roleMembers = Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId
    foreach ($member in $roleMembers) {
        if ($member.ObjectType -eq "User") {
            try {
                $licenses = Get-AzureADUserLicenseDetail -ObjectId $member.ObjectId
                if (-not ($licenses.SkuId -contains $p1SkuId) -and -not ($licenses.SkuId -contains $p2SkuId)) {
                    $adminsWithoutLicenses += [PSCustomObject]@{
                        DisplayName       = $member.DisplayName
                        UserPrincipalName = $member.UserPrincipalName
                        RoleName          = $role.DisplayName
                    }
                }
            } catch { continue }
        }
    }
}
$adminsWithoutLicenses | Export-Csv -Path "$outputDirectory\AdminsWithoutP1P2_1.3.csv" -NoTypeInformation -Encoding UTF8
Write-Host "Exported admins without P1/P2 licenses to AdminsWithoutP1P2_1.3.csv. Total: $($adminsWithoutLicenses.Count)"

# --- Control 1.4: Users Without MFA Enabled
Write-Host "Fetching users without MFA enabled..."
$usersWithoutMFA = @()
$allMsolUsers = Get-MsolUser -All
foreach ($user in $allMsolUsers) {
    if ($user.StrongAuthenticationMethods.Count -eq 0) {
        $usersWithoutMFA += $user
    }
}
$usersWithoutMFA | Select-Object DisplayName, UserPrincipalName | Export-Csv -Path "$outputDirectory\UsersWithoutMFA_1.4.csv" -NoTypeInformation -Encoding UTF8
Write-Host "Exported users without MFA to UsersWithoutMFA_1.4.csv. Total: $($usersWithoutMFA.Count)"

# --- Control 1.5: Non-Cloud-Only Privileged Admins
Write-Host "Fetching non-cloud-only privileged admins..."
$nonCloudAdmins = @()
foreach ($role in $adminRoles) {
    $roleMembers = Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId
    foreach ($member in $roleMembers) {
        if ($member.ObjectType -eq "User" -and -not [string]::IsNullOrEmpty($member.ImmutableId)) {
            $nonCloudAdmins += [PSCustomObject]@{
                DisplayName       = $member.DisplayName
                UserPrincipalName = $member.UserPrincipalName
                RoleName          = $role.DisplayName
                ImmutableId       = $member.ImmutableId
            }
        }
    }
}
if ($nonCloudAdmins.Count -gt 0) {
    $nonCloudAdmins | Export-Csv -Path "$outputDirectory\NonCloudOnlyAdmins.csv" -NoTypeInformation -Encoding UTF8
    Write-Host "Exported non-cloud-only privileged admins to NonCloudOnlyAdmins.csv. Total: $($nonCloudAdmins.Count)"
} else {
    "DisplayName,UserPrincipalName,RoleName,ImmutableId" | Out-File -FilePath "$outputDirectory\NonCloudOnlyAdmins.csv" -Encoding utf8
    Write-Host "No non-cloud-only privileged admin accounts found. This meets the MS.AAD.7.3v1 control requirement."
}

# --- Cleanup
Write-Host "Cleaning up by removing the AzureAD and MSOnline modules..."
Remove-Module $moduleName -ErrorAction SilentlyContinue
Remove-Module $msolModuleName -ErrorAction SilentlyContinue

Write-Host "Data collection complete: Global Admins, Admins without P1/P2, Non-cloud admins, Users without MFA."

Write-Host "Data collection for grabbing all Non-cloud-only Admins, Admins without a P1 or P2 license, all users without MFA, and all global admins is complete."
