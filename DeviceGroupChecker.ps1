
# DeviceGroupChecker.ps1

# === Module Check for ImportExcel Only ===
$installedByScript = @()

# Check and install ImportExcel if needed
if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
    Write-Host "'ImportExcel' not found. Installing from PowerShell Gallery..." -ForegroundColor Yellow
    Install-Module -Name ImportExcel -Scope CurrentUser -Force -ErrorAction Stop
    $installedByScript += "ImportExcel"
}

Import-Module ActiveDirectory
Import-Module ImportExcel

# === Create Output Folder ===
$outputFolder = "$PSScriptRoot\ADReports"
New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null

# === Gather AD Data ===
$allComputers = Get-ADComputer -Filter * -Properties OperatingSystem
$allComputerNames = $allComputers | Select-Object -ExpandProperty Name
$allGroups = Get-ADGroup -Filter *

$deviceOnlyGroups = @()
$mixedGroups = @()
$workstationOnlyGroups = @()
$groupedComputers = @()
$workstationOnlyDetails = @()
$mixedGroupDetails = @()

foreach ($group in $allGroups) {
    $members = Get-ADGroupMember -Identity $group.DistinguishedName -Recursive | Where-Object { $_.objectClass -eq "computer" }

    if ($members.Count -gt 0) {
        $serverCount = 0
        $workstationCount = 0
        $workstations = @()
        $isMixedGroup = $false

        foreach ($member in $members) {
            $computer = Get-ADComputer -Identity $member.SamAccountName -Properties OperatingSystem
            $groupedComputers += $computer.Name
            $type = "Workstation"

            if ($computer.OperatingSystem -like "*server*") {
                $type = "Server"
                $serverCount++
            } else {
                $workstationCount++
                $workstations += $computer.Name
            }

            if ($serverCount -gt 0 -and $workstationCount -gt 0) {
                $isMixedGroup = $true
            }

            $mixedGroupDetails += [PSCustomObject]@{
                GroupName    = $group.Name
                ComputerName = $computer.Name
                Type         = $type
            }
        }

        if ($isMixedGroup) {
            $mixedGroups += [PSCustomObject]@{
                GroupName        = $group.Name
                ServerCount      = $serverCount
                WorkstationCount = $workstationCount
            }
        } elseif ($serverCount -eq 0 -and $workstationCount -gt 0) {
            $deviceOnlyGroups += $group
            $workstationOnlyGroups += [PSCustomObject]@{
                GroupName        = $group.Name
                WorkstationCount = $workstationCount
            }

            foreach ($ws in $workstations) {
                $workstationOnlyDetails += [PSCustomObject]@{
                    GroupName    = $group.Name
                    Workstation  = $ws
                }
            }
        }
    }
}

# === Report: Computers Not in Any Group ===
$groupedComputers = $groupedComputers | Sort-Object -Unique
$missingComputers = $allComputerNames | Where-Object { $_ -notin $groupedComputers }

if ($missingComputers.Count -gt 0) {
    $missingComputers | Sort-Object | ForEach-Object {
        [PSCustomObject]@{ 'ComputerName' = $_ }
    } | Export-Excel -Path "$outputFolder\UngroupedComputers.xlsx" -AutoSize
}

# === Export: Mixed Groups ===
if ($mixedGroups.Count -gt 0) {
    $mixedGroups | Export-Excel -Path "$outputFolder\MixedGroups.xlsx" -AutoSize
}
if ($mixedGroupDetails.Count -gt 0) {
    $mixedGroupDetails | Export-Excel -Path "$outputFolder\MixedGroups_Detailed.xlsx" -AutoSize
}

# === Export: Workstation-Only Groups ===
if ($workstationOnlyGroups.Count -gt 0) {
    $workstationOnlyGroups | Export-Excel -Path "$outputFolder\WorkstationOnlyGroups.xlsx" -AutoSize
}
if ($workstationOnlyDetails.Count -gt 0) {
    $workstationOnlyDetails | Export-Excel -Path "$outputFolder\WorkstationOnlyGroups_Detailed.xlsx" -AutoSize
}

# === Console Summary ===
Write-Host "`n==== AD Computer Group Coverage Report ====" -ForegroundColor Cyan
Write-Host "Total AD Computers: $($allComputerNames.Count)"
Write-Host "Total Computers in Device-Only Groups: $($groupedComputers.Count)"
Write-Host "Computers NOT in Any Device-Only Group: $($missingComputers.Count)`n"

if ($missingComputers.Count -gt 0) {
    Write-Host "Exported ungrouped devices to UngroupedComputers.xlsx" -ForegroundColor Yellow
} else {
    Write-Host "All AD computer objects are included in device-only groups. No ungrouped computers found." -ForegroundColor Green
}

if ($mixedGroups.Count -gt 0) {
    Write-Host "Exported mixed groups to MixedGroups.xlsx and MixedGroups_Detailed.xlsx" -ForegroundColor Red
} else {
    Write-Host "No groups contain both servers and non-servers." -ForegroundColor Green
}

if ($workstationOnlyGroups.Count -gt 0) {
    Write-Host "Exported workstation-only groups to WorkstationOnlyGroups.xlsx and WorkstationOnlyGroups_Detailed.xlsx" -ForegroundColor Cyan
} else {
    Write-Host "No workstation-only groups found." -ForegroundColor Yellow
}

# === Clean Up ImportExcel if installed by script ===
foreach ($mod in $installedByScript) {
    if ($mod -eq "ImportExcel") {
        Write-Host "`nCleaning up module: $mod" -ForegroundColor DarkGray
        Uninstall-Module -Name $mod -AllVersions -Force
    }
}
