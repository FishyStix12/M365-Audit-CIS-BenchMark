# Check for Active Directory module
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "Active Directory module is not installed. Cleaning up environment..." -ForegroundColor Yellow

    Remove-Variable allComputers, deviceOnlyGroups, groupedComputers, missingComputers, mixedGroups, workstationOnlyGroups -ErrorAction SilentlyContinue
    Write-Host "Please install the RSAT: Active Directory module before running this script." -ForegroundColor Red
    return
}

Import-Module ActiveDirectory

# Step 1: Get all AD computers with OS info
$allComputers = Get-ADComputer -Filter * -Properties OperatingSystem | Select-Object Name, OperatingSystem
$allComputerNames = $allComputers.Name

# Step 2: Get all AD groups with only computer objects
$deviceOnlyGroups = Get-ADGroup -Filter * | Where-Object {
    $members = Get-ADGroupMember -Identity $_.DistinguishedName -Recursive -ErrorAction SilentlyContinue
    $members.Count -gt 0 -and ($members | Where-Object { $_.objectClass -ne 'computer' }).Count -eq 0
}

# Step 3: Classify group contents
$groupedComputers = @()
$mixedGroups = @()
$workstationOnlyGroups = @()

foreach ($group in $deviceOnlyGroups) {
    $members = Get-ADGroupMember -Identity $group.DistinguishedName -Recursive | Where-Object { $_.objectClass -eq 'computer' }

    $servers = @()
    $nonServers = @()

    foreach ($member in $members) {
        $comp = Get-ADComputer -Identity $member.DistinguishedName -Properties OperatingSystem
        if ($comp.OperatingSystem -like "*Server*") {
            $servers += $comp.Name
        } else {
            $nonServers += $comp.Name
        }
        $groupedComputers += $comp.Name
    }

    if ($servers.Count -gt 0 -and $nonServers.Count -gt 0) {
        $mixedGroups += [PSCustomObject]@{
            GroupName        = $group.Name
            ServerCount      = $servers.Count
            WorkstationCount = $nonServers.Count
            Servers          = ($servers -join ', ')
            Workstations     = ($nonServers -join ', ')
        }
    } elseif ($servers.Count -eq 0 -and $nonServers.Count -gt 0) {
        $workstationOnlyGroups += [PSCustomObject]@{
            GroupName        = $group.Name
            WorkstationCount = $nonServers.Count
            Workstations     = ($nonServers -join ', ')
        }
    }
}

# Step 4: Find computers not in any device-only group
$groupedComputers = $groupedComputers | Sort-Object -Unique
$missingComputers = $allComputerNames | Where-Object { $_ -notin $groupedComputers }

# Step 5: Output summary
Write-Host "`n==== AD Computer Group Coverage Report ====" -ForegroundColor Cyan
Write-Host "Total AD Computers: $($allComputerNames.Count)"
Write-Host "Total Computers in Device-Only Groups: $($groupedComputers.Count)"
Write-Host "Computers NOT in Any Device-Only Group: $($missingComputers.Count)`n"

if ($missingComputers.Count -gt 0) {
    Write-Host "Devices not in any device-only group:" -ForegroundColor Yellow
    $missingComputers | Sort-Object | Format-Table -AutoSize
} else {
    Write-Host "All AD computer objects are included in device-only groups. No ungrouped computers found." -ForegroundColor Green
}

if ($mixedGroups.Count -gt 0) {
    Write-Host "`nWARNING: The following groups contain a mix of servers and non-servers:" -ForegroundColor Red
    $mixedGroups | Format-Table GroupName, ServerCount, WorkstationCount -AutoSize
} else {
    Write-Host "`nNo groups contain both servers and non-servers." -ForegroundColor Green
}

if ($workstationOnlyGroups.Count -gt 0) {
    Write-Host "`nGroups containing ONLY non-server (workstation) computers — suitable for Intune targeting:" -ForegroundColor Cyan
    $workstationOnlyGroups | Format-Table GroupName, WorkstationCount -AutoSize
} else {
    Write-Host "`nNo workstation-only groups found." -ForegroundColor Yellow
}
