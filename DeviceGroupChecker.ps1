Import-Module ActiveDirectory

# Step 1: Get all computers in AD
$allComputers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

# Step 2: Get all groups where all members are computers
$deviceOnlyGroups = Get-ADGroup -Filter * | Where-Object {
    $members = Get-ADGroupMember -Identity $_.DistinguishedName -Recursive -ErrorAction SilentlyContinue
    $members.Count -gt 0 -and ($members | Where-Object { $_.objectClass -ne 'computer' }).Count -eq 0
}

# Step 3: Get all computers from those groups
$groupedComputers = @()
foreach ($group in $deviceOnlyGroups) {
    $groupedComputers += Get-ADGroupMember -Identity $group.DistinguishedName -Recursive | Select-Object -ExpandProperty Name
}

# Step 4: Compare lists to find uncovered computers
$groupedComputers = $groupedComputers | Sort-Object -Unique
$missingComputers = $allComputers | Where-Object { $_ -notin $groupedComputers }

# Output results
Write-Host "`nTotal Computers in AD: $($allComputers.Count)"
Write-Host "Total Computers in Device-Only Groups: $($groupedComputers.Count)"
Write-Host "Computers NOT in Any Device-Only Group: $($missingComputers.Count)"

# Optional: list them
$missingComputers | Sort-Object | Format-Table -AutoSize
