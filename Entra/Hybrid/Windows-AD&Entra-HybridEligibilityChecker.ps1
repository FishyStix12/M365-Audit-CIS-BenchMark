#################################################################################################
# Author: Nicholas Fisher
# Date: April 9 2025
# Description of Script
# Windows-AD&Entra-HybridEligibilityChecker.ps1 - helps support a multi-stage hybrid join rollout into Entra by 
# separating Windows 11 and Windows Server devices. It allows you to onboard in phases, making 
# it easier to test, track, and manage device readiness. By checking OS versions and grouping 
# devices, it enables targeting through Entra groups for things like Intune auto-enrollment and 
# policy assignments tied to hybrid-joined status.
#################################################################################################
# === Module Check for ImportExcel Only ===
$installedByScript = @()

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

# === Gather Windows-Only AD Computer Objects ===
$allComputers = Get-ADComputer -Filter * -Properties OperatingSystem | Where-Object {
    $_.OperatingSystem -match "Windows"
}
$allComputerNames = $allComputers | Select-Object -ExpandProperty Name
$allGroups = Get-ADGroup -Filter *

# === Initialize Collections ===
$deviceOnlyGroups = @()
$mixedGroups = @()
$workstationOnlyGroups = @()
$groupedComputers = @()
$workstationOnlyDetails = @()
$mixedGroupDetails = @()

# === Analyze Group Membership ===
foreach ($group in $allGroups) {
    $members = Get-ADGroupMember -Identity $group.DistinguishedName -Recursive | Where-Object { $_.objectClass -eq "computer" }

    if ($members.Count -gt 0) {
        $serverCount = 0
        $workstationCount = 0
        $workstations = @()
        $isMixedGroup = $false

        foreach ($member in $members) {
            $computer = Get-ADComputer -Identity $member.SamAccountName -Properties OperatingSystem
            if ($computer.OperatingSystem -notmatch "Windows") { continue }

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

# === Identify Devices Ineligible for Hybrid Join ===
$ineligibleHybridJoin = @()

foreach ($computer in $allComputers) {
    $os = $computer.OperatingSystem
    $name = $computer.Name

    $isEligible = $false

    if ($os -match "Windows 10") {
        if ($os -match "Windows 10.*?(\d{4})") {
            $version = [int]$matches[1]
            if ($version -ge 1607) { $isEligible = $true }
        } else {
            $isEligible = $true
        }
    }
    elseif ($os -match "Windows 11") {
        $isEligible = $true
    }
    elseif ($os -match "Windows Server") {
        if ($os -match "2016|2019|2022") {
            $isEligible = $true
        }
    }

    if (-not $isEligible) {
        $ineligibleHybridJoin += [PSCustomObject]@{
            ComputerName     = $name
            OperatingSystem  = $os
        }
    }
}

if ($ineligibleHybridJoin.Count -gt 0) {
    $ineligibleHybridJoin | Export-Excel -Path "$outputFolder\IneligibleForHybridJoin.xlsx" -AutoSize
    Write-Host "Exported devices ineligible for Hybrid Join to IneligibleForHybridJoin.xlsx" -ForegroundColor Yellow
} else {
    Write-Host "All devices meet the OS version requirements for Hybrid Join." -ForegroundColor Green
}

# === Export: All Windows Devices - Append to TXT Instead of Excel ===
$windowsDevices = Get-ADComputer -Filter * -Properties OperatingSystem, OperatingSystemVersion | Where-Object {
    $_.OperatingSystem -match "Windows"
}

$reportFile = Join-Path $outputFolder "AllWindowsDevices_Detailed.txt"

"==== Windows AD Devices Report ====" | Out-File -FilePath $reportFile -Encoding UTF8
$windowsDevices | ForEach-Object {
    $line = "Name: $($_.Name) | ObjectGUID: $($_.ObjectGUID) | OS: $($_.OperatingSystem) | Version: $($_.OperatingSystemVersion)"
    $line | Out-File -FilePath $reportFile -Append -Encoding UTF8
}

Write-Host "Appended all Windows device details to AllWindowsDevices_Detailed.txt" -ForegroundColor Cyan

# === Console Summary ===
Write-Host "`n==== AD Computer Group Coverage Report ====" -ForegroundColor Cyan
Write-Host "Total Windows AD Computers: $($allComputerNames.Count)"
Write-Host "Total Computers in Device-Only Groups: $($groupedComputers.Count)"
Write-Host "Computers NOT in Any Device-Only Group: $($missingComputers.Count)"
Write-Host "Total Devices Ineligible for Hybrid Join: $($ineligibleHybridJoin.Count)`n"

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

if ($ineligibleHybridJoin.Count -gt 0) {
    Write-Host "Some devices are ineligible for Hybrid Join. See IneligibleForHybridJoin.xlsx" -ForegroundColor DarkYellow
} else {
    Write-Host "All devices appear to meet Hybrid Join OS requirements." -ForegroundColor Green
}

# === Clean Up ImportExcel if installed by script ===
foreach ($mod in $installedByScript) {
    if ($mod -eq "ImportExcel") {
        Write-Host "`nCleaning up module: $mod" -ForegroundColor DarkGray
        Remove-Module -Name $mod -Force -ErrorAction SilentlyContinue
        try {
            Uninstall-Module -Name $mod -AllVersions -Force -ErrorAction Stop
            Write-Host "Module '$mod' successfully uninstalled." -ForegroundColor Green
        } catch {
            Write-Warning "Failed to uninstall module '$mod': $_"
        }
    }
}
