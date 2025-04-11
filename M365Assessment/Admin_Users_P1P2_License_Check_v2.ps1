<#
.SYNOPSIS
Cloud Shell Safe: Audits AAD admin roles for P1/P2 license compliance.

.NOTES
Run only in environments where Microsoft.Graph is pre-installed and pre-loaded (e.g., Azure Cloud Shell).
#>

$outputDirectory = Join-Path $HOME -ChildPath "Scripts-M365Assessment-Reports"
if (-not (Test-Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory | Out-Null
}

# Skip module handling entirely; Cloud Shell has Graph preloaded
try {
    Connect-MgGraph -Scopes "User.Read.All", "Directory.Read.All", "RoleManagement.Read.Directory"
} catch {
    Write-Error "Graph connection failed. Exiting."
    exit
}

# Get P1/P2 license SKU IDs
$skus = Get-MgSubscribedSku
$p1Sku = $skus | Where-Object { $_.SkuPartNumber -eq "ENTERPRISEPREMIUM" }
$p2Sku = $skus | Where-Object { $_.SkuPartNumber -eq "ENTERPRISEPREMIUM2" }
$p1SkuId = $p1Sku.SkuId
$p2SkuId = $p2Sku.SkuId

# Get all admin role definitions
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
                        Write-Warning "
