#################################################################################################
# Author: Nicholas Fisher
# Date: January 23 2025
# Description of Script
# This PowerShell script automates the assessment of Microsoft 365 Admin Center (M365) 
# configurations against specific security and compliance controls, as defined by the CIS M365 
# Benchmark. It performs tasks such as importing and managing required modules, verifying 
# administrative account configurations, checking global administrator count, evaluating license 
# assignments for privileged users, assessing public group approvals, and auditing critical 
# tenant-wide settings like password expiration, external calendar sharing, and the customer 
# lockbox feature. Each control's results are compiled into detailed reports stored in a central
# location. The script also manages cleanup processes to maintain a clean environment.
#################################################################################################

# Define the custom module path
$customModulePath = ".\powershell\modules"

# Install necessary modules
Save-Module -Name Az -Scope CurrentUser -Force -Path $customModulePath
Save-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force -Path $customModulePath

#Adds custom module path to the environment variable PSModulePath.
$env:PSModulePath += $customModulePath

# Import necessary modules
Import-Module -Name "$customModulePath\Az" -Prefix Custom -Scope Global -Force
Import-Module -Name "$customModulePath\ExchangeOnlineManagement" -Prefix Custom -Scope Global -Force

# Check if the modules are imported successfully
if (-not (Get-Module -Name AzureAD)) { Write-Error "AzureAD module not imported" }
if (-not (Get-Module -Name ExchangeOnlineManagement)) { Write-Error "ExchangeOnlineManagement module not imported" }

#Get tenant ID
$tenantID = Read-Host-Host "Please enter your tenant ID to connect to Azure AD:"

#  Connect to Account
# Connect to Azure AD with the necessary permissions for directory roles and user data.
Connect-AzAccount -TenantId $tenatID

# Connect to Exchange Online
Connect-ExchangeOnline

# Control 1.1.1: Ensure Administrative accounts are cloud-only.
#  Initialize the report
$Report = [System.Collections.Generic.List[Object]]::new()

# Add a message specifying the control being implemented.
$Control = "1.1.1: Ensure Administrative accounts are cloud-only."
$Report.Add($Control)

# Get privileged role IDs
$PrivilegedRoles = Get-RoleGroup | Where-Object { $_.Name -like "*Administrator*" -or $_.Name -eq "Global Reader" }

# Get the members of these various roles
$RoleMembers = $PrivilegedRoles | ForEach-Object { Get-RoleGroupMember -Identity $_.Identity } | Select-Object Id -Unique

# Retrieve details about the members in these roles
$PrivilegedUsers = $RoleMembers | ForEach-Object { Get-User -Identity $_.Id -Properties UserPrincipalName, DisplayName, Id, OnPremisesSyncEnabled }

# Check if any privileged users have an on-premises or hybrid account
$HybridUsers = $PrivilegedUsers | Where-Object { $_.OnPremisesSyncEnabled -eq $true }

if ($HybridUsers.Count -gt 0) {
    # Output the hybrid users and indicate that the control failed
    $output = "Control failed: The following privileged users have on-premises or hybrid accounts:"
    $output2 = $HybridUsers | Format-Table DisplayName, UserPrincipalName, OnPremisesSyncEnabled
    $Report.Add($output)
    $Report.Add($output2)
} else {
    # Indicate that the control passed
    $output = "Control passed: No privileged users have on-premises or hybrid accounts. All are cloud-only."
    $Report.Add($output)
}

# Join the formatted report entries into a single string and save it to a text file.
$Report -join "`n" | Add-Content -Path "C:\Reports\M365AdminCenter.txt"

# Control 1.1.3: Ensure that between two and four global admins are designated. 
#  Initialize the report
$Report2 = [System.Collections.Generic.List[Object]]::new()

# Add a message specifying the control being implemented.
$Control2 = "1.1.3: Ensure that between two and four global admins are designated."
$Report2.Add($Control2)

$globalAdminRole = Get-MgDirectoryRole -Filter "RoleTemplateId eq '62e90394- 69f5-4237-9190-012177145e10'" 
$globalAdmins = Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id 
if ($globalAdmins.count -ge 2 -and $globalAdmins.count -le 4) {
    # Indicate that the control passed
    $output = "Control passed: Between two and four global admins are designated."
    $output2 = $globalAdmins | Format-Table DisplayName, UserPrincipalName, Id
    $Report2.Add($output)
    $Report2.Add($output2)
} else {
    # Output the global admins and indicate that the control failed
    $output = "Control failed: The number of global admins is not between two and four."
    $output2 = $globalAdmins | Format-Table DisplayName, UserPrincipalName, Id
    $Report2.Add($output)
    $Report2.Add($output2)
}

# Join the formatted report entries into a single string and save it to a text file.
$Report2 -join "`n" | Add-Content -Path "C:\Reports\M365AdminCenter.txt"

# Control: 1.1.4 Ensure administrative accounts use licenses with a reduced application footprint.
#  Retrieve all directory roles in the tenant
# This retrieves all roles in the directory (e.g., Global Admin, Exchange Admin, etc.).
# - `Get-AzureADDirectoryRole`: Fetches all directory roles in the Azure AD tenant.
$DirectoryRoles = Get-AzureADDirectoryRole

#  Filter privileged roles
# Only include roles that have "Administrator" in their name or are "Global Reader."
# - `Where-Object`: Filters objects based on specified criteria.
# - `-like`: String comparison operator for pattern matching.
$PrivilegedRoles = $DirectoryRoles | Where-Object { 
    $_.DisplayName -like "*Administrator*" -or $_.DisplayName -eq "Global Reader" 
}

#  Get the members of these roles
# For each role, retrieve the list of users assigned to it. We filter for unique user IDs.
# - `ForEach-Object`: Iterates over each object in the input.
# - `Get-AzureADDirectoryRoleMember`: Retrieves members of a specified directory role.
# - `Select-Object`: Selects specific properties of an object.
# - `-Unique`: Ensures unique entries.
$RoleMembers = $PrivilegedRoles | ForEach-Object { 
    Get-AzureADDirectoryRoleMember -ObjectId $_.ObjectId 
} | Select-Object ObjectId -Unique

#  Retrieve detailed information for privileged users
# For every member of these roles, fetch user details like DisplayName, UserPrincipalName, and ObjectId.
# - `Get-AzureADUser`: Fetches detailed information about a specified user.
$PrivilegedUsers = $RoleMembers | ForEach-Object { 
    Get-AzureADUser -ObjectId $_.ObjectId -Property UserPrincipalName, DisplayName, ObjectId 
}

#  Initialize the report and counters
# Create an empty list to store the report data for each user.
# - `[System.Collections.Generic.List[Object]]::new()`: Creates a new generic list to store objects.
# Also, initialize counters to count the number of True and False values for P1/P2 licenses.
$Report3 = [System.Collections.Generic.List[Object]]::new()
$TrueCount = 0
$FalseCount = 0

# Add a message specifying the control being implemented.
$Control3 = "Control: 1.1.4 Ensure administrative accounts use licenses with a reduced application footprint."
$Report3.Add($Control3)

#  Build the report for each user
foreach ($Admin in $PrivilegedUsers) {
    # Retrieve the licenses assigned to the user
    # - `(Get-AzureADUserLicenseDetail -ObjectId $Admin.ObjectId).SkuPartNumber`: Retrieves license details for the user and joins them into a single string.
    $License = $null
    $License = (Get-AzureADUserLicenseDetail -ObjectId $Admin.ObjectId).SkuPartNumber -join ", "

    # Check if the user has an Entra Premium P1 or P2 license
    # The SKU part numbers are "AAD_PREMIUM_P1" and "AAD_PREMIUM_P2"
    # - `-match`: Checks if the string matches the specified pattern.
    $HasP1OrP2 = if ($License -match "AAD_PREMIUM_P1|AAD_PREMIUM_P2") {
        $true
    } else {
        $false
    }

    # Increment counters based on the license check
    if ($HasP1OrP2) {
        $TrueCount++
    } else {
        $FalseCount++
    }

    # Create a row for this user with the required data
    # - `[pscustomobject][ordered]@{}`: Creates an ordered custom object with specified properties.
    $Object = [pscustomobject][ordered]@{
        DisplayName       = $Admin.DisplayName       # User's full name
        UserPrincipalName = $Admin.UserPrincipalName # User's email address
        License           = $License                # Licenses assigned to the user
        HasP1OrP2         = $HasP1OrP2              # True or False for Entra P1/P2 license
    }

    # Add this user's data to the report
    $Report3.Add($Object)
}

#  Add counts to the report
# Create objects to store the counts of True and False values and add them to the report.
$TrueObject = [pscustomobject][ordered]@{
    CountType = "Has Entra Premium P1 or P2 License"
    Count     = $TrueCount
}
$FalseObject = [pscustomobject][ordered]@{
    CountType = "Does Not Have Entra Premium P1 or P2 License"
    Count     = $FalseCount
}
$Report3.Add($TrueObject)
$Report3.Add($FalseObject)

# Format the report entries for better readability.
# - `ForEach-Object`: Iterates over each object to format it.
# - `Out-String`: Converts objects to a string representation.
# - `Set-Content`: Writes the formatted string to a specified file.
$FormattedReport = $Report3 | ForEach-Object {
    if ($_ -is [pscustomobject]) {
        "DisplayName: $_.DisplayName`nUserPrincipalName: $_.UserPrincipalName`nLicense: $_.License`nHasP1OrP2: $_.HasP1OrP2`n"
    } else {
        $_
    }
}
$FormattedReport -join "`n" | Set-Content -Path "C:\Reports\M365AdminCenter.txt"

# Control 1.2.1: Ensure that only organizationally managed/approved public groups exist.
# Initialize the report 
$Report4 = [System.Collections.Generic.List[Object]]::new()

# Add control message to the report
$Control4 = "Control: 1.2.1 Ensure that only organizationally managed/approved public groups exist."
$Report4.Add($Control4)

# Prompt the user to enter approved group names
$ApprovedGroups = @()
while ($true) {
    $groupName = Read-Host -Prompt "Enter the name of an approved public group (or press Enter to finish)"
    if ([string]::IsNullOrWhiteSpace($groupName)) {
        break
    }
    $ApprovedGroups += $groupName
}

# Retrieve all public groups in the tenant
# This retrieves all groups that are public.
# Retrieve all public groups in the tenant
# This retrieves all groups that are public.
# - `Get-AzureADGroup`: Retrieves all groups, filtering by the group type 'Unified' and visibility 'Public'.
# Retrieve all groups and filter for public groups
$PublicGroups = Get-AzureADGroup | Where-Object { $_.GroupTypes -contains "Unified" -and $_.Visibility -eq "Public" }

# Check if public groups are approved
# Loop through each public group and check if it is in the list of approved groups.
# - `Where-Object`: Filters groups that are not in the list of approved groups.
$NonApprovedGroups = $PublicGroups | Where-Object { -not ($ApprovedGroups -contains $_.DisplayName) }

# Output the approval status of each group
foreach ($Group in $PublicGroups) {
    if ($ApprovedGroups -contains $Group.DisplayName) {
        Write-Host "Group '$($Group.DisplayName)' is approved."
    } else {
        Write-Host "Group '$($Group.DisplayName)' is NOT approved."
    }
}

# Generate a report of non-approved groups
# Create a report for any groups that are not approved.
$NonApprovedGroups | ForEach-Object {
    $GroupObject = [pscustomobject][ordered]@{
        DisplayName = $_.DisplayName
        Visibility  = $_.Visibility
    }
    $Report4.Add($GroupObject)
}

# Save the report to a text file
# Format the report entries for better readability.
$FormattedReport2 = $Report4 | ForEach-Object {
    if ($_ -is [pscustomobject]) {
        "DisplayName: $_.DisplayName`nVisibility: $_.Visibility`n"
    } else {
        $_
    }
}
$FormattedReport2 -join "`n" | Set-Content -Path "C:\Reports\M365AdminCenter.txt"

# Control 1.2.2: Ensure sign-in to shared mailboxes is blocked.

#  Initialize the report 
# Create a new list to store the report data for each shared mailbox.
$Report5 = [System.Collections.Generic.List[Object]]::new()

#  Add control message to the report
$Control5 = "Control: 1.2.2 Ensure sign-in to shared mailboxes is blocked."
$Report5.Add($Control5)

# Retrieve all shared mailboxes in the tenant
# Get all mailboxes that are of type 'SharedMailbox'.
$MBX = Get-EXOMailbox -RecipientTypeDetails SharedMailbox

$MBX | ForEach-Object {
    # Get user details for the shared mailbox using its ExternalDirectoryObjectId.
    $user = Get-MsolUser -ObjectId $_.ExternalDirectoryObjectId
    # Add the user details to the report, including whether sign-in is allowed.
    $Report5.Add([PSCustomObject]@{
        DisplayName = $user.DisplayName
        UserPrincipalName = $user.UserPrincipalName
        AccountEnabled = $user.AccountEnabled
        # Determine if sign-in is allowed based on the AccountEnabled property.
        SignInAllowed = if ($user.AccountEnabled) { $true } else { $false }
    })
}

# Count the true and false values
# Count the number of shared mailboxes where sign-in is allowed (true).
$trueCount = ($Report5 | Where-Object { $_.SignInAllowed -eq $true }).Count
# Count the number of shared mailboxes where sign-in is blocked (false).
$falseCount = ($Report5 | Where-Object { $_.SignInAllowed -eq $false }).Count

# Output the counts
# Add the counts of true and false values to the report.
$Report5.Add("True (Sign-in allowed): $trueCount")
$Report5.Add("False (Sign-in blocked): $falseCount")

# Display the report
# Format the report as a table for better readability.
$Report5 | Format-Table -AutoSize

# Save the report to a text file
# Format the report entries for better readability.
$FormattedReport3 = $Report5 | ForEach-Object {
    if ($_ -is [PSCustomObject]) {
        "DisplayName: $_.DisplayName`nUserPrincipalName: $_.UserPrincipalName`nAccountEnabled: $_.AccountEnabled`nSignInAllowed: $_.SignInAllowed`n"
    } else {
        $_
    }
}
# Join the formatted report entries into a single string and save it to a text file.
$FormattedReport3 -join "`n" | Set-Content -Path "C:\Reports\M365AdminCenter.txt"

# Control 1.3.1: Ensure the 'Password expiration policy' is set to 'Set passwords to never expire (recommended)'.
# Initialize the report
# Create a new list to store the report data for each shared mailbox.
$Report6 = [System.Collections.Generic.List[Object]]::new()

# Add control message to the report
$Control6 = "Ensure the 'Password expiration policy' is set to 'Set passwords to never expire (recommended)'."
$Report6.Add($Control6)

# Retrieve password expiration policy for each domain
$Domains = Get-MgDomain | Select-Object Id, PasswordValidityPeriodInDays

# Initialize a list to store invalid domains
$InvalidDomains = @()

# Check password expiration policy for each domain
foreach ($Domain in $Domains) {
    if ($Domain.PasswordValidityPeriodInDays -ne 2147483647) {
        $InvalidDomains += $Domain
    }
}

# Determine the control result
if ($InvalidDomains.Count -gt 0) {
    $output = "Control failed: Password expiration policy is not set to 'Set passwords to never expire (recommended)' for the following domains:"
    $InvalidDomains | ForEach-Object {
        $Report6.Add("Domain: $($_.Id), PasswordValidityPeriodInDays: $($_.PasswordValidityPeriodInDays)")
    }
} else {
    $output = "Control passed: Password expiration policy is set to 'Set passwords to never expire (recommended)' for all domains."
}

# Add the output to the report
$Report6.Add($output)

# Join the formatted report entries into a single string and save it to a text file.
$Report6 -join "`n" | Set-Content -Path "C:\Reports\M365AdminCenter.txt"

# Control 1.3.3: Ensure 'External sharing' of calendars is not available. 
# Initialize the report
# Create a new list to store the report data for each shared mailbox.
$Report7 = [System.Collections.Generic.List[Object]]::new()

# Add control message to the report
$Control7 = "1.3.3: Ensure 'External sharing' of calendars is not available."
$Report7.Add($Control7)

$Share = Get-SharingPolicy -Identity "Default Sharing Policy" 

if ($Share.Enabled -eq $false) {
    $output = "Control passed: External sharing of calendars is not available."
} else {
    $output = "Control failed: External sharing of calendars is available."
}
$Report7.Add($output)

# Join the formatted report entries into a single string and save it to a text file.
$Report7 -join "`n" | Set-Content -Path "C:\Reports\M365AdminCenter.txt"

# Control 1.3.6: Ensure the customer lockbox feature is enabled.
# Initialize the report
# Create a new list to store the report data for each shared mailbox.
$Report8 = [System.Collections.Generic.List[Object]]::new()

# Add control message to the report
$Control8 = "1.3.6: Ensure the customer lockbox feature is enabled."
$Report8.Add($Control8)

$Lockbox =  Get-OrganizationConfig | Select-Object CustomerLockBoxEnabled
if ($Lockbox.CustomerLockBoxEnabled -eq $true) {
    $output = "Control passed: Customer lockbox feature is enabled."
} else {
    $output = "Control failed: Customer lockbox feature is not enabled."
}
$Finished = "Finished running all automated controls for M365 Admin Center."
Report8.Add($output)
Report8.Add($Finished)

# Join the formatted report entries into a single string and save it to a text file.
$Report8 -join "`n" | Set-Content -Path "C:\Reports\M365AdminCenter.txt"

#Removes the Custom Module path from the environment.
$env:PSModulePath = $env:PSModulePath -replace [regex]::Escape($customModulePath + ';'), ''

# Deletes the customModulePath directories and modules from the client Environment. Finished the cleanup process.
Remove-Item -Path $customModulePath -Recurse -Force
