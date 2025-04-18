
#################################################################################################
# Author: Nicholas Fisher
# Date: April 10 2025
# Description:
# This script audits all Azure AD roles containing "Admin" or "Administrator" in their names.
# It filters to include only user objects (excluding service accounts and apps), and reports
# which users are missing P1 or P2 licenses.
#################################################################################################

# Set output directory
$outputDirectory = Join-Path -Path $PSScriptRoot -ChildPath "Scripts-M365Assessment-Reports"
if (-not (Test-Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory | Out-Null
}

# Required modules
$moduleName = 'AzureAD'
$msolModuleName = 'MSOnline'

if (-not (Get-Module -ListAvailable -Name $moduleName)) {
    Install-Module -Name $moduleName -Force -Scope CurrentUser
}
if (-not (Get-Module -ListAvailable -Name $msolModuleName)) {
    Install-Module -Name $msolModuleName -Force -Scope CurrentUser
}

Import-Module $moduleName
Import-Module $msolModuleName

# Connect to services
Connect-AzureAD | Out-Null
Connect-MsolService | Out-Null

# Get P1 and P2 license SKUs
Write-Host "Auditing admin roles containing 'Admin' or 'Administrator' for P1/P2 license compliance..."
$sku = Get-AzureADSubscribedSku
$p1SkuId = ($sku | Where-Object { $_.SkuPartNumber -eq "ENTERPRISEPREMIUM" }).SkuId
$p2SkuId = ($sku | Where-Object { $_.SkuPartNumber -eq "ENTERPRISEPREMIUM2" }).SkuId

# Dynamically filter admin roles
$allRoles = Get-AzureADDirectoryRole
$adminRoles = $allRoles | Where-Object { $_.DisplayName -match "Admin|Administrator" }

$adminsWithoutLicenses = @()

foreach ($role in $adminRoles) {
    $roleMembers = Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId
    foreach ($member in $roleMembers) {
        # Exclude non-user objects (e.g., service principals, groups)
        if ($member.ObjectType -ne "User") {
            continue
        }

        try {
            $licenses = Get-AzureADUserLicenseDetail -ObjectId $member.ObjectId
            if (-not ($licenses.SkuId -contains $p1SkuId) -and -not ($licenses.SkuId -contains $p2SkuId)) {
                $adminsWithoutLicenses += [PSCustomObject]@{
                    DisplayName       = $member.DisplayName
                    UserPrincipalName = $member.UserPrincipalName
                    RoleName          = $role.DisplayName
                }
            }
        } catch {
            continue
        }
    }
}

# Export results
$outputFilePath = Join-Path $outputDirectory -ChildPath "AdminsMissingP1P2.csv"
if ($adminsWithoutLicenses.Count -gt 0) {
    $adminsWithoutLicenses | Export-Csv -Path $outputFilePath -NoTypeInformation -Encoding UTF8
    Write-Host "Exported results to: $outputFilePath. Total non-compliant users: $($adminsWithoutLicenses.Count)"
} else {
    Write-Host "All admin users found in filtered roles have valid P1 or P2 licenses. No CSV created."
}

# Cleanup
Remove-Module $moduleName -ErrorAction SilentlyContinue
Remove-Module $msolModuleName -ErrorAction SilentlyContinue

Write-Host "Filtered admin role license audit complete."
