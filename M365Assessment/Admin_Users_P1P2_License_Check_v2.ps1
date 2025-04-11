<#
.SYNOPSIS
Audits all Azure AD roles containing "Admin" or "Administrator" and finds users without P1 or P2 licenses.

.AUTHOR
Nicholas Fisher

.LAST UPDATED
April 11, 2025
#>

# Set output directory
$outputDirectory = Join-Path -Path $PSScriptRoot -ChildPath "Scripts-M365Assessment-Reports"
if (-not (Test-Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory | Out-Null
}

# Force TLS 1.2 for PowerShell Gallery access
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Install NuGet provider silently if missing
if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
    Write-Host "NuGet provider not found. Installing..."
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
    Import-PackageProvider -Name NuGet -Force
}

# Install Microsoft.Graph module if not already installed
$graphModule = "Microsoft.Graph"
if (-not (Get-Module -ListAvailable -Name $graphModule)) {
    Write-Host "Microsoft.Graph module not found. Attempting installation..."
    try {
        Install-Module $graphModule -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
    } catch {
        Write-Warning "Microsoft.Graph module could not be installed. It may be in use or locked."
    }
}

# Import Microsoft.Graph module
try {
    Import-Module $graphModule -Force -ErrorAction Stop
} catch {
    Write-Warning "Microsoft.Graph module could not be fully imported. Some components may already be loaded."
}

# Connect to Microsoft Graph
Connect-MgGraph -Scopes "User.Read.All", "Directory.Read.All", "RoleManagement.Read.Directory"

# Retrieve P1 and P2 SKU IDs
$skus = Get-MgSubscribedSku
$p1Sku = $skus | Where-Object { $_.SkuPartNumber -eq "ENTERPRISEPREMIUM" }
$p2Sku = $skus | Where-Object { $_.SkuPartNumber -eq "ENTERPRISEPREMIUM2" }
$p1SkuId = $p1Sku.SkuId
$p2SkuId = $p2Sku.SkuId

# Filter roles with "admin" or "administrator" in the name
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

# Export results
$outputFile = Join-Path $outputDirectory -ChildPath "AdminsMissingP1P2.csv"
if ($usersWithoutP1P2.Count -gt 0) {
    $usersWithoutP1P2 | Sort-Object UserPrincipalName | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
    Write-Host "Exported results to: $outputFile. Total non-compliant users: $($usersWithoutP1P2.Count)"
} else {
    Write-Host "All admin users have P1 or P2 licenses. No CSV created."
}

# Cleanup session
Disconnect-MgGraph
try {
    Get-Module Microsoft.Graph* | Remove-Module -Force -ErrorAction Stop
    Write-Host "Graph session disconnected and modules removed."
} catch {
    Write-Warning "Modules are currently in use and could not be removed. This will not impact results."
}

# Cleanup
Disconnect-MgGraph
Remove-Module Microsoft.Graph -Force -ErrorAction SilentlyContinue
Write-Host "Graph session disconnected and module removed. Script complete."
