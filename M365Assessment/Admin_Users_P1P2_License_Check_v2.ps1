<#
.SYNOPSIS
Audits all Azure AD roles containing "Admin" or "Administrator" and finds users without P1 or P2 licenses.

.AUTHOR
Nicholas Fisher

.LAST UPDATED
April 11, 2025
#>

# Define output folder
$outputDirectory = Join-Path -Path $PSScriptRoot -ChildPath "Scripts-M365Assessment-Reports"
if (-not (Test-Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory | Out-Null
}

# Check, install, and import Microsoft.Graph if needed
$graphModule = "Microsoft.Graph"
$graphInstalled = Get-Module -ListAvailable -Name $graphModule

if (-not $graphInstalled) {
    Write-Host "Microsoft.Graph module not found. Installing..."
    Install-Module $graphModule -Scope CurrentUser -Force
}

Import-Module $graphModule -Force

# Connect to Microsoft Graph with required scopes
Connect-MgGraph -Scopes "User.Read.All", "Directory.Read.All", "RoleManagement.Read.Directory"

# Retrieve P1/P2 SKU IDs dynamically
$skus = Get-MgSubscribedSku
$p1Sku = $skus | Where-Object { $_.SkuPartNumber -eq "ENTERPRISEPREMIUM" }
$p2Sku = $skus | Where-Object { $_.SkuPartNumber -eq "ENTERPRISEPREMIUM2" }
$p1SkuId = $p1Sku.SkuId
$p2SkuId = $p2Sku.SkuId

# Retrieve admin roles dynamically
$allRoles = Get-MgRoleManagementDirectoryRoleDefinition -Filter "isBuiltIn eq true"
$adminRoles = $allRoles | Where-Object { $_.DisplayName -match "admin|administrator" }

$usersWithoutP1P2 = @()

foreach ($role in $adminRoles) {
    $assignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$($role.Id)'" -ExpandProperty "Principal"

    foreach ($assignment in $assignments) {
        $principal = $assignment.Principal
        $objectType = $principal.'@odata.type'

        if ($objectType -eq "#microsoft.graph.user") {
            $upn = $principal.UserPrincipalName
            try {
                $user = Get-MgUser -UserId $upn -Property "Id,UserPrincipalName,DisplayName,AssignedLicenses"
                $hasValidLicense = $user.AssignedLicenses | Where-Object {
                    $_.SkuId -eq $p1SkuId -or $_.SkuId -eq $p2SkuId
                }
                if (-not $hasValidLicense) {
                    $usersWithoutP1P2 += [PSCustomObject]@{
                        DisplayName       = $user.DisplayName
                        UserPrincipalName = $user.UserPrincipalName
                        RoleName          = $role.DisplayName
                    }
                }
            } catch {
                Write-Warning "Failed to check license for $upn"
            }
        }
        elseif ($objectType -eq "#microsoft.graph.group") {
            $groupId = $principal.Id
            try {
                $groupMembers = Get-MgGroupMember -GroupId $groupId -All | Where-Object {
                    $_.'@odata.type' -eq "#microsoft.graph.user"
                }

                foreach ($member in $groupMembers) {
                    $upn = $member.UserPrincipalName
                    try {
                        $user = Get-MgUser -UserId $upn -Property "Id,UserPrincipalName,DisplayName,AssignedLicenses"
                        $hasValidLicense = $user.AssignedLicenses | Where-Object {
                            $_.SkuId -eq $p1SkuId -or $_.SkuId -eq $p2SkuId
                        }
                        if (-not $hasValidLicense) {
                            $usersWithoutP1P2 += [PSCustomObject]@{
                                DisplayName       = $user.DisplayName
                                UserPrincipalName = $user.UserPrincipalName
                                RoleName          = $role.DisplayName
                            }
                        }
                    } catch {
                        Write-Warning "Failed to check license for $upn"
                    }
                }
            } catch {
                Write-Warning "Failed to resolve members of group $groupId"
            }
        }
    }
}

# Export results to CSV
$outputFile = Join-Path $outputDirectory -ChildPath "AdminsMissingP1P2.csv"
if ($usersWithoutP1P2.Count -gt 0) {
    $usersWithoutP1P2 | Sort-Object UserPrincipalName | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
    Write-Host "Exported results to: $outputFile. Total non-compliant users: $($usersWithoutP1P2.Count)"
} else {
    Write-Host "All admin users have P1 or P2 licenses. No CSV created."
}

# Cleanup
Disconnect-MgGraph
Remove-Module Microsoft.Graph -Force -ErrorAction SilentlyContinue
Write-Host "Graph session disconnected and module removed. Script complete."
