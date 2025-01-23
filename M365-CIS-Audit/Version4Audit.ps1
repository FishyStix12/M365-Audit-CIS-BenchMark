#################################################################################################
# Author: Nicholas Fisher
# Date: January 23 2025
# Description of Script
# The provided PowerShell script is designed to support auditing and management of Microsoft 365
# environments based on Version 4.0 of the CIS M365 Benchmark. It defines a custom module path
# and installs essential PowerShell modules, including Az, PnP.PowerShell, AzureAD, MSOnline,
# and ExchangeOnlineManagement, to facilitate automated security assessments. The script aims
# to streamline the evaluation of M365 configurations against the CIS Benchmark, ensuring
# compliance with security best practices and enhancing the overall security posture.
#################################################################################################
# Define the custom module path
$customModulePath = ".\powershell\modules"

# Install necessary modules
Save-Module -Name Az -Scope CurrentUser -Force -Path $customModulePath
Save-Module -Name PnP.PowerShell -Scope CurrentUser -Force -Path $customModulePath
Save-Module -Name AzureAD -Scope CurrentUser -Force -Path $customModulePath
Save-Module -Name MSOnline -Scope CurrentUser -Force -Path $customModulePath
Save-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force -Path $customModulePath
Save-Module -Name MicrosoftTeams -Scope CurrentUser -Force -Path $customModulePath
Save-Module -Name SharePointPnPPowerShellOnline -Scope CurrentUser -Force -Path $customModulePath
Save-Module -Name AzPurview -Scope CurrentUser -Force -Path $customModulePath

$env:PSModulePath += $customModulePath

# Find module directory, update modules path. 

# Import necessary modules
Import-Module -Name "$customModulePath\Az" -Prefix Custom -Scope Global -Force
Import-Module -Name "$customModulePath\PnP.PowerShell" -Prefix Custom -Scope Global -Force
Import-Module -Name "$customModulePath\AzureAD" -Prefix Custom -Scope Global -Force
Import-Module -Name "$customModulePath\MSOnline" -Prefix Custom -Scope Global -Force
Import-Module -Name "$customModulePath\ExchangeOnlineManagement" -Prefix Custom -Scope Global -Force
Import-Module -Name "$customModulePath\MicrosoftTeams" -Prefix Custom -Scope Global -Force
Import-Module -Name "$customModulePath\SharePointPnPPowerShellOnline" -Prefix Custom -Scope Global -Force
Import-Module -Name "$customModulePath\AzPurview" -Prefix Custom -Scope Global -Force

# Check if the modules are imported successfully
if (-not (Get-Module -Name AzureAD)) { Write-Error "AzureAD module not imported" }
if (-not (Get-Module -Name MSOnline)) { Write-Error "MSOnline module not imported" }
if (-not (Get-Module -Name ExchangeOnlineManagement)) { Write-Error "ExchangeOnlineManagement module not imported" }
if (-not (Get-Module -Name MicrosoftTeams)) { Write-Error "MicrosoftTeams module not imported" }
if (-not (Get-Module -Name SharePointPnPPowerShellOnline)) { Write-Error "SharePointPnPPowerShellOnline module not imported" }
if (-not (Get-Module -Name AzPurview)) { Write-Error "AzPurview module not imported" }

#Get tenant ID
$tenatID = (Get-AzContext).Tenant.Id

#  Connect to Account
# Connect to Azure AD with the necessary permissions for directory roles and user data.
Connect-AzAccount -TenantId $tenantID

# Connect to Exchange Online
Connect-ExchangeOnline

# Connect to Microsoft Teams
Connect-MicrosoftTeams

# Connect to SharePoint Online
$tenantURL = Read-Host -Prompt "Please enter your SharePoint Tenant URL: "
Connect-PnPOnline -Url "$($tenantURL)"
#If command above doesn't work, try this:
Connect-SPOService -Url "$($tenantURL)"

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
$Report = [System.Collections.Generic.List[Object]]::new()
$TrueCount = 0
$FalseCount = 0

# Add a message specifying the control being implemented.
$Control = "Control: 1.1.4 Ensure administrative accounts use licenses with a reduced application footprint."
$Report.Add($Control)

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
    $Report.Add($Object)
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
$Report.Add($TrueObject)
$Report.Add($FalseObject)

# Format the report entries for better readability.
# - `ForEach-Object`: Iterates over each object to format it.
# - `Out-String`: Converts objects to a string representation.
# - `Set-Content`: Writes the formatted string to a specified file.
$FormattedReport = $Report | ForEach-Object {
    if ($_ -is [pscustomobject]) {
        "DisplayName: $_.DisplayName`nUserPrincipalName: $_.UserPrincipalName`nLicense: $_.License`nHasP1OrP2: $_.HasP1OrP2`n"
    } else {
        $_
    }
}
$FormattedReport -join "`n" | Set-Content -Path "C:\Reports\M365AdminCenter.txt"

# Control 1.2.1: Ensure that only organizationally managed/approved public groups exist.
#  Initialize the report for 1.2.1
$Report2 = [System.Collections.Generic.List[Object]]::new()

#  Add control message to the report
$Control2 = "Control: 1.2.1 Ensure that only organizationally managed/approved public groups exist."
$Report2.Add($Control2)

#  Retrieve all public groups in the tenant
# This retrieves all groups that are public.
# - `Get-MgGroup`: Retrieves all groups, filtering by the group type 'Unified' and visibility 'Public'.
$PublicGroups = Get-MgGroup -Filter "groupTypes/any(c:c eq 'Unified')" -Property DisplayName,Visibility -All | Where-Object { $_.Visibility -eq "Public" }

#  Define the list of approved groups
-
# Define a list of approved public groups. This should be managed by your organization.
$ApprovedGroups = @(
    "Approved Group 1",
    "Approved Group 2",
    "Approved Group 3"
)

#  Check if public groups are approved
# Loop through each public group and check if it is in the list of approved groups.
# - `Where-Object`: Filters groups that are not in the list of approved groups.
$NonApprovedGroups = $PublicGroups | Where-Object { -not ($ApprovedGroups -contains $_.DisplayName) }

#  Output the approval status of each group
foreach ($Group in $PublicGroups) {
    if ($ApprovedGroups -contains $Group.DisplayName) {
        Write-Host "Group '$($Group.DisplayName)' is approved."
    } else {
        Write-Host "Group '$($Group.DisplayName)' is NOT approved."
    }
}

# STEP 8: Generate a report of non-approved groups
# Create a report for any groups that are not approved.
$NonApprovedGroups | ForEach-Object {
    $GroupObject = [pscustomobject][ordered]@{
        DisplayName = $_.DisplayName
        Visibility  = $_.Visibility
    }
    $Report2.Add($GroupObject)
}

# Save the report to a text file
# Format the report entries for better readability.
$FormattedReport2 = $Report2 | ForEach-Object {
    if ($_ -is [pscustomobject]) {
        "DisplayName: $_.DisplayName`nVisibility: $_.Visibility`n"
    } else {
        $_
    }
}
$FormattedReport2 -join "`n" | Set-Content -Path "C:\Reports\M365AdminCenter.txt"

# Control 1.2.2: Ensure sign-in to shared mailboxes is blocked.

#  Initialize the report for 1.2.2
# Create a new list to store the report data for each shared mailbox.
$Report3 = [System.Collections.Generic.List[Object]]::new()

#  Add control message to the report

$Control3 = "Control: 1.2.2 Ensure sign-in to shared mailboxes is blocked."
$Report3.Add($Control3)

# Retrieve all shared mailboxes in the tenant
# Get all mailboxes that are of type 'SharedMailbox'.
$MBX = Get-EXOMailbox -RecipientTypeDetails SharedMailbox

# Loop through each shared mailbox and retrieve user details
$MBX | ForEach-Object {
    # Get user details for the shared mailbox using its ExternalDirectoryObjectId.
    $user = Get-MgUser -UserId $_.ExternalDirectoryObjectId -Property DisplayName, UserPrincipalName, AccountEnabled
    # Add the user details to the report, including whether sign-in is allowed.
    $Report3.Add([PSCustomObject]@{
        DisplayName = $user.DisplayName
        UserPrincipalName = $user.UserPrincipalName
        AccountEnabled = $user.AccountEnabled
        # Determine if sign-in is allowed based on the AccountEnabled property.
        SignInAllowed = if ($user.AccountEnabled) { $true } else { $false }
    })
}

# Count the true and false values
# Count the number of shared mailboxes where sign-in is allowed (true).
$trueCount = ($Report3 | Where-Object { $_.SignInAllowed -eq $true }).Count
# Count the number of shared mailboxes where sign-in is blocked (false).
$falseCount = ($Report3 | Where-Object { $_.SignInAllowed -eq $false }).Count

# Output the counts
# Add the counts of true and false values to the report.
$Report3.Add("True (Sign-in allowed): $trueCount")
$Report3.Add("False (Sign-in blocked): $falseCount")

# Display the report
# Format the report as a table for better readability.
$Report3 | Format-Table -AutoSize

# Save the report to a text file
# Format the report entries for better readability.
$FormattedReport3 = $Report3 | ForEach-Object {
    if ($_ -is [PSCustomObject]) {
        "DisplayName: $_.DisplayName`nUserPrincipalName: $_.UserPrincipalName`nAccountEnabled: $_.AccountEnabled`nSignInAllowed: $_.SignInAllowed`n"
    } else {
        $_
    }
}
# Join the formatted report entries into a single string and save it to a text file.
$FormattedReport3 -join "`n" | Set-Content -Path "C:\Reports\M365AdminCenter.txt"

# Control 2.2.13: Ensure the connection filter safe list is off.

#  Initialize the report for 2.2.13
# Create a new list to store the report data for this control.
$Report4 = [System.Collections.Generic.List[Object]]::new()

#  Add control message to the report

# Add a message specifying the control being implemented.
$Control4 = "Control: 2.2.13 Ensure the connection filter safe list is off."
$Report4.Add($Control4)

# Connect to Exchange Online to retrieve the Hosted Connection Filter Policy.
Connect-ExchangeOnline

#  Run the following PowerShell command to get the Hosted Connection Filter Policy
# Retrieve the Hosted Connection Filter Policy for the default identity and format the output to list the EnableSafeList property.
$FilterPolicy = Get-HostedConnectionFilterPolicy -Identity Default | Format-List EnableSafeList

#  Ensure EnableSafeList is False
# Check if the EnableSafeList property is set to False and add the result to the report.
if ($FilterPolicy.EnableSafeList -eq $false) {
    $Report4.Add("EnableSafeList is False")
} else {
    $Report4.Add("EnableSafeList is not False")
}

#  Save the updated report to the text file
# Format the report entries for better readability.
$FormattedReport4 = $Report4 | ForEach-Object {
    if ($_ -is [PSCustomObject]) {
        "Control: 2.2.13 Ensure the connection filter safe list is off.`nEnableSafeList: $_"
    } else {
        $_
    }
}
#  Join the formatted report entries into a single string and append it to the text file.
$FormattedReport4 -join "`n" | Add-Content -Path "C:\Reports\M365AdminCenter.txt"

# Control 2.2.14: Ensure inbound anti-spam policies do not contain allowed domains.

#  Initialize the report 
# Create a new list to store the report data for this control.
$Report5 = [System.Collections.Generic.List[Object]]::new()

#  Add control message to the report

# Add a message specifying the control being implemented.
$Control5 = "Control: 2.2.14 Ensure inbound anti-spam policies do not contain allowed domains."
$Report5.Add($Control5)

#  Connect to Exchange Online
# Connect to Exchange Online to retrieve the Hosted Content Filter Policy.
Connect-ExchangeOnline

#  Run the following PowerShell command to get the Hosted Content Filter Policy
# Retrieve the Hosted Content Filter Policy and format the output to list the Identity and AllowedSenderDomains properties.
$ContentFilterPolicies = Get-HostedContentFilterPolicy | Select-Object Identity, AllowedSenderDomains

#  Ensure AllowedSenderDomains is undefined for each inbound policy
# Loop through each policy and check if AllowedSenderDomains is undefined.
$ContentFilterPolicies | ForEach-Object {
    $PolicyStatus = if ($_.AllowedSenderDomains -eq $null -or $_.AllowedSenderDomains.Count -eq 0) {
        "AllowedSenderDomains is undefined"
    } else {
        "AllowedSenderDomains is defined"
    }
    # Add the policy details and status to the report.
    $Report5.Add([PSCustomObject]@{
        Identity = $_.Identity
        AllowedSenderDomains = $_.AllowedSenderDomains -join ", "
        Status = $PolicyStatus
    })
}

#  Save the report to a text file
# Format the report entries for better readability.
$FormattedReport5 = $Report5 | ForEach-Object {
    if ($_ -is [PSCustomObject]) {
        "Identity: $_.Identity`nAllowedSenderDomains: $_.AllowedSenderDomains`nStatus: $_.Status`n"
    } else {
        $_
    }
}
#  Join the formatted report entries into a single string and save it to a text file.
$FormattedReport5 -join "`n" | Set-Content -Path "C:\Reports\M365AdminCenter.txt"

# Control 6.5.1: Ensure Modern Authentication for Exchange Online is enabled
#  Initialize the report 
# Create a new list to store the report data for this control.
$Report6 = [System.Collections.Generic.List[Object]]::new()

#  Add control message to the report

# Add a message specifying the control being implemented.
$Control6 = "Control 6.5.1: Ensure Modern Authentication for Exchange Online is enabled."
$Report6.Add($Control6)

#  Run the following Powershell command:
$Auth = Get-OrganizationConfig | Select-Object Name, OAuth*

#  Add the authentication configuration details to the report
$FormattedReport6 = [System.Collections.Generic.List[Object]]::new()
$FormattedReport6.Add("Modern Authentication Configuration:")
$FailedCount = 0
$NonCompliantAccounts = [System.Collections.Generic.List[Object]]::new()
$Auth | ForEach-Object {
    $Report6.Add("Name: $($_.Name), OAuth: $($_.OAuth)")
    if ($_.OAuth -eq $false) {
        $FailedCount++
        $NonCompliantAccounts.Add($_.Name)
    }
}

# Add the summary of failed accounts to the report
$SummaryCount = "Total number of accounts with OAuth disabled: $FailedCount"
$Report6.Add($SummaryCount)
$FormattedReport6.Add($SummaryCount)

# Add the list of noncompliant accounts to the report
if ($FailedCount -gt 0) {
    $NonCompliantSummary = "Accounts noncompliant: " + ($NonCompliantAccounts -join ", ")
    $Report6.Add($NonCompliantSummary)
    $FormattedReport6.Add($NonCompliantSummary)
}

#  Join the formatted report entries into a single string and save it to a text file.

$FormattedReport6 -join "`n" | Set-Content -Path "C:\Reports\M365AdminCenter.txt"

# Control 7.2.2: Ensure SharePoint and OneDrive integration with Azure AD B2B is enabled.
#  Initialize the report 
# Create a new list to store the report data for this control.
$Report7 = [System.Collections.Generic.List[Object]]::new()

#  Add control message to the report

# Add a message specifying the control being implemented.
$Control7 = "Control 7.2.2: Ensure SharePoint and OneDrive integration with Azure AD B2B is enabled."
$Report7.Add($Control7)

#  Run the following Powershell Command

$B2B = Get-SPOTenant | Select-Object -ExpandProperty EnableAzureADB2BIntegration
if ($B2B -eq $false) {
    $output = "Azure AD B2B integration is not enabled between SharePoint and OneDrive. Control failed."
}
else {
    $output = "Azure AD B2B integration is enabled between SharePoint and OneDrive. Control passed."
}
$Report7.Add("EnableAzureADB2BIntegration: $B2B")
$Report7.Add($output)

#  Join the formatted report entries into a single string and save it to a text file.

$Report7 -join "`n" | Set-Content -Path "C:\Reports\M365AdminCenter.txt"

#Control 7.2.3: Ensure external content sharing is restricted.
#  Initialize the report 
# Create a new list to store the report data for this control.
$Report8 = [System.Collections.Generic.List[Object]]::new()

# Add a message specifying the control being implemented.
$Control8 = "7.2.3: Ensure external content sharing is restricted."
$Report8.Add($Control8)

#  Run the following Powershell Command
$exShare = Get-SPOTenant | Select-Object -ExpandProperty SharingCapability
if ($exShare -eq "ExternalUserSharingOnly" -or $exShare -eq "ExistingExternalUserSharingOnly" -or $exShare -eq "Disabled") {
    $output = "External content sharing is restricted. Control passed."
}
else {
    $output = "External content sharing is not restricted. Control failed."
}
$Report8.Add("SharingCapability: $exShare")
$Report8.Add($output)

#  Join the formatted report entries into a single string and save it to a text file.
$Report8 -join "`n" | Set-Content -Path "C:\Reports\M365AdminCenter.txt"

# Control 7.2.7: Ensure link sharing is restricted in SharePoint and OneDrive.
#  Initialize the report 
# Create a new list to store the report data for this control.
$Report9 = [System.Collections.Generic.List[Object]]::new()

#  Add control message to the report
# Add a message specifying the control being implemented.
$Control9 = "7.2.7: Ensure link sharing is restricted in SharePoint and OneDrive."
$Report9.Add($Control9)

#  Run the following Powershell Command
$LinkSharking = Get-SPOTenant | fl DefaultSharingLinkType
if ($LinkSharking -eq "Direct") {
    $output = "Link sharing is restricted. Control passed."
}
else {
    $output = "Link sharing is not restricted. Control failed."
}
Report9.Add($LinkSharking)
Report9.Add($output)

#  Join the formatted report entries into a single string and save it to a text file.
$Report9 -join "`n" | Set-Content -Path "C:\Reports\M365AdminCenter.txt"

# Control 7.2.9: Ensure guest access to a site or OneDrive will expire automatically.
#  Initialize the report 
# Create a new list to store the report data for this control.
$Report10 = [System.Collections.Generic.List[Object]]::new()

# Add a message specifying the control being implemented.
$Control10 = "7.2.9: Ensure guest access to a site or OneDrive will expire automatically."
$Report10.Add($Control0)

#  Run the following Powershell Command
$UserExpire = Get-SPOTenant | fl ExternalUserExpirationRequired
$DaysExpire = Get-SPOTenant | fl ExternalUserExpireInDays
if ($UserExpire -eq "True") {
    $output = "Guest access will expire automatically. Control passed."
}
else {
    $output = "Guest access will not expire automatically. Control failed."
}
if ($DaysExpire -le "30") {
    $output2 = "Guest access will expire in 30 days. Control passed."
}
else {
    $output2 = "Guest access will not expire in 30 days. Control failed."
}
$Report10.Add($UserExpire)
$Report10.Add($DaysExpire)
$Report10.Add($output)
$Report10.Add($output2)

#  Join the formatted report entries into a single string and save it to a text file.
$Report10 -join "`n" | Set-Content -Path "C:\Reports\M365AdminCenter.txt"

# Control 7.2.11: Ensure the SharePoint default sharing link permission is set.
# Create a new list to store the report data for this control.
$Report11 = [System.Collections.Generic.List[Object]]::new()

# Add a message specifying the control being implemented.
$Control11 = "7.2.11: Ensure the SharePoint default sharing link permission is set."
$Report11.Add($Control11)

#  Run the following Powershell Command
$LinkPermission = Get-SPOTenant | fl DefaultLinkPermission
if ($LinkPermission -eq "View") {
    $output = "Default sharing link permission is set to View. Control passed."
}
else {
    $output = "Default sharing link permission is not set to View. Control failed."
}
$Report11.Add($LinkPermission)
$Report11.Add($output)

#  Join the formatted report entries into a single string and save it to a text file.
$Report11 -join "`n" | Set-Content -Path "C:\Reports\M365AdminCenter.txt"

# Control 7.3.1: Ensure Office 365 SharePoint infected files are disallowed for download. 
# Create a new list to store the report data for this control.
$Report12 = [System.Collections.Generic.List[Object]]::new()

#  Add control message to the report

# Add a message specifying the control being implemented.
$Control12 = "7.3.1: Ensure Office 365 SharePoint infected files are disallowed for download."
$Report12.Add($Control12)

#  Run the following Powershell Command
$InfectFiles = Get-SPOTenant | Select-Object DisallowInfectedFileDownload 
if ($InfectFiles.DisallowInfectedFileDownload -eq $true) {
    $output = "Infected files are disallowed for download. Control passed."
}
else {
    $output = "Infected files are allowed for download. Control failed."
}
Report12.Add($InfectFiles)
Report12.Add($output)

#  Join the formatted report entries into a single string and save it to a text file.
$Report12 -join "`n" | Set-Content -Path "C:\Reports\M365AdminCenter.txt"

# Control 8.1.1: Ensure external file sharing in Teams is enabled for only approved cloud storage services.
# Create a new list to store the report data for this control.
$Report13 = [System.Collections.Generic.List[Object]]::new()

# Add a message specifying the control being implemented.
$Control13 = "8.1.1: Ensure external file sharing in Teams is enabled for only approved cloud storage services."
$Report13.Add($Control13)

#  Run the following PowerShell Command
$ApprovedServices = Get-CsTeamsClientConfiguration | fl AllowDropbox,AllowBox,AllowGoogleDrive,AllowShareFile,AllowEgnyte

# Convert the output to a string
$ApprovedServicesString = $ApprovedServices | Out-String

# Append the control message and the output to the text file
$Report13.Add($ApprovedServicesString)
$Report13 -join "`n" | Add-Content -Path "C:\Reports\M365AdminCenter.txt"

# Control 8.1.2: Ensure users can't send emails to a channel email address.
# Create a new list to store the report data for this control.
$Report14 = [System.Collections.Generic.List[Object]]::new()

# Add a message specifying the control being implemented.
$Control14 = "8.1.2: Ensure users can't send emails to a channel email address."
$Report14.Add($Control14)

#  Run the following PowerShell Command
$ChannelAddress = Get-CsTeamsClientConfiguration -Identity Global | fl AllowEmailIntoChannel 
if ($ChannelAddress.AllowEmailIntoChannel -eq $false) {
    $output = "Users can't send emails to a channel email address. Control passed."
}
else {
    $output = "Users can send emails to a channel email address. Control failed."
}
Report14.Add($ChannelAddress)
Report14.Add($output)

#  Join the formatted report entries into a single string and save it to a text file.
$Report14 -join "`n" | Set-Content -Path "C:\Reports\M365AdminCenter.txt"

# Control 8.2.1: Ensure external domains are restricted in the Teams admin center.
# Create a new list to store the report data for this control.
$Report15 = [System.Collections.Generic.List[Object]]::new()

# Add a message specifying the control being implemented.
$Control15 = "8.2.1: Ensure external domains are restricted in the Teams admin center."
$Report15.Add($Control15)

#  Run the following PowerShell Command
$FedUsers = Get-CsTenantFederationConfiguration | Select-Object -ExpandProperty AllowFederatedUsers
$AllowedDomains = Get-CsTenantFederationConfiguration | Select-Object -ExpandProperty AllowedDomains

if ($FedUsers -eq $false) {
    $output = "External domains are restricted in the Teams admin center. Control passed."
} elseif ($FedUsers -eq $true -and $AllowedDomains -ne "AllowAllKnownDomains") {
    $output = "External domains are restricted in the Teams admin center. Control passed."
} else {
    $output = "External domains are not restricted in the Teams admin center. Control failed."
}

# Add the output to the report
$Report15.Add("AllowFederatedUsers: $FedUsers")
$Report15.Add("AllowedDomains: $AllowedDomains")
$Report15.Add($output)

# Join the formatted report entries into a single string and save it to a text file.
$Report15 -join "`n" | Set-Content -Path "C:\Reports\M365AdminCenter.txt"

# Control 8.2.2: Ensure communication with unmanaged Teams users is disabled. 
# Create a new list to store the report data for this control.
$Report16 = [System.Collections.Generic.List[Object]]::new()

# Add a message specifying the control being implemented.
$Control16 = "8.2.2: Ensure communication with unmanaged Teams users is disabled."
$Report16.Add($Control16)

#  Run the following PowerShell Command
$TeamsComms = Get-CsTenantFederationConfiguration | fl AllowTeamsConsumer 
if ($TeamsComms.AllowTeamsConsumer -eq $false) {
    $output = "Communication with unmanaged Teams users is disabled. Control passed."
}
else {
    $output = "Communication with unmanaged Teams users is enabled. Control failed."
}
Report16.Add($TeamsComms)
Report16.Add($output)

#  Join the formatted report entries into a single string and save it to a text file.
$Report16 -join "`n" | Set-Content -Path "C:\Reports\M365AdminCenter.txt"

# Control 8.2.3: Ensure external Teams users cannot initiate conversations.
# Create a new list to store the report data for this control.
$Report17 = [System.Collections.Generic.List[Object]]::new()

# Add a message specifying the control being implemented.
$Control17 = "8.2.3: Ensure external Teams users cannot initiate conversations."
$Report17.Add($Control17)

#  Run the following PowerShell Command
$Inbound = Get-CsTenantFederationConfiguration | fl AllowTeamsConsumerInbound 
if ($Inbound.AllowTeamsConsumerInbound -eq $false) {
    $output = "External Teams users cannot initiate conversations. Control passed."
}
else {
    $output = "External Teams users can initiate conversations. Control failed."
}
Report17.Add($Inbound)
Report17.Add($output)

#  Join the formatted report entries into a single string and save it to a text file.
$Report17 -join "`n" | Set-Content -Path "C:\Reports\M365AdminCenter.txt"

# Control 8.5.1: Ensure anonymous users can't join a meeting.
# Create a new list to store the report data for this control.
$Report18 = [System.Collections.Generic.List[Object]]::new()

# Add a message specifying the control being implemented.
$Control18 = "8.5.1: Ensure anonymous users can't join a meeting."
$Report18.Add($Control18)

#  Run the following PowerShell Command
$Anonjoin = Get-CsTeamsMeetingPolicy -Identity Global | fl AllowAnonymousUsersToJoinMeeting 
if ($Anonjoin.AllowAnonymousUsersToJoinMeeting -eq $false) {
    $output = "Anonymous users can't join a meeting. Control passed."
}
else {
    $output = "Anonymous users can join a meeting. Control failed."
}
Report18.Add($Anonjoin)
Report18.Add($output)

#  Join the formatted report entries into a single string and save it to a text file.
$Report18 -join "`n" | Set-Content -Path "C:\Reports\M365AdminCenter.txt"

# Control 8.5.2: Ensure anonymous users and dial-in callers can't start a meeting.
# Create a new list to store the report data for this control.
$Report19 = [System.Collections.Generic.List[Object]]::new()

# Add a message specifying the control being implemented.
$Control19 = "8.5.2: Ensure anonymous users and dial-in callers can't start a meeting."
$Report19.Add($Control19)

# Run the following PowerShell Command
$AnonDialer = Get-CsTeamsMeetingPolicy -Identity Global | fl AllowAnonymousUsersToStartMeeting 
if ($AnonDialer.AllowAnonymousUsersToStartMeeting -eq $false) {
    $output = "Anonymous users and dial-in callers can't start a meeting. Control passed."
}
else {
    $output = "Anonymous users and dial-in callers can start a meeting. Control failed."
}
Report19.Add($AnonDialer)
Report19.Add($output)

#  Join the formatted report entries into a single string and save it to a text file.
$Report19 -join "`n" | Set-Content -Path "C:\Reports\M365AdminCenter.txt"

# Control 8.5.3: Ensure only people in my org can bypass the lobby.
# Create a new list to store the report data for this control.
$Report20 = [System.Collections.Generic.List[Object]]::new()

# Add a message specifying the control being implemented.
$Control20 = "8.5.3: Ensure only people in my org can bypass the lobby."
$Report20.Add($Control20)

# Run the following PowerShell Command
$LobBypass = Get-CsTeamsMeetingPolicy -Identity Global | fl AutoAdmittedUsers
if ($LobBypass.AutoAdmittedUsers -eq "EveryoneInCompanyExcludingGuests") {
    $output = "Only people in my org can bypass the lobby. Control passed."
}
else {
    $output = "People outside my org can bypass the lobby. Control failed."
}
Report20.Add($LobBypass)
Report20.Add($output)

#  Join the formatted report entries into a single string and save it to a text file.
$Report20 -join "`n" | Set-Content -Path "C:\Reports\M365AdminCenter.txt"

# Control 8.5.5: Ensure meeting chat does not allow anonymous users.
# Create a new list to store the report data for this control.
$Report21 = [System.Collections.Generic.List[Object]]::new()

# Add a message specifying the control being implemented.
$Control21 = "8.5.5: Ensure meeting chat does not allow anonymous users."
$Report21.Add($Control21)

# Run the following PowerShell Command
$BlockAnon = Get-CsTeamsMeetingPolicy -Identity Global | fl MeetingChatEnabledType
if ($BlockAnon.MeetingChatEnabledType -eq "DisabledForAnonymousUsers" -or $BlockAnon.MeetingChatEnabledType -eq "EnabledExceptAnonymous") {
    $output = "Meeting chat does not allow anonymous users. Control passed."
}
else {
    $output = "Meeting chat allows anonymous users. Control failed."
}
$Report21.Add($BlockAnon)
$Report21.Add($output)

#  Join the formatted report entries into a single string and save it to a text file.
$Report21 -join "`n" | Set-Content -Path "C:\Reports\M365AdminCenter.txt"

#Control 8.5.6: Ensure only organizers and co-organizers can present.
# Create a new list to store the report data for this control.
$Report22 = [System.Collections.Generic.List[Object]]::new()

# Add a message specifying the control being implemented.
$Control22 = "8.5.6: Ensure only organizers and co-organizers can present."
$Report22.Add($Control22)

# Run the following PowerShell Command
$CoOrg = Get-CsTeamsMeetingPolicy -Identity Global | fl DesignatedPresenterRoleMode 
if ($CoOrg.DesignatedPresenterRoleMode -eq "OrganizerOnly" -or $CoOrg.DesignatedPresenterRoleMode -eq "CoOrganizerAndOrganizer" -or $CoOrg.DesignatedPresenterRoleMode -eq "OrganizerOnlyUserOverride") {
    $output = "Only organizers and co-organizers can present. Control passed."
}
else {
    $output = "Other participants can present. Control failed."
}
$Report22.Add($CoOrg)
$Report22.Add($output)

#  Join the formatted report entries into a single string and save it to a text file.
$Report22 -join "`n" | Set-Content -Path "C:\Reports\M365AdminCenter.txt"

# Control 8.5.8: Ensure external meeting chat is off.
# Create a new list to store the report data for this control.
$Report23 = [System.Collections.Generic.List[Object]]::new()

# Add a message specifying the control being implemented.
$Control23 = "8.5.8: Ensure external meeting chat is off."
$Report23.Add($Control23)

# Run the following PowerShell Command
$ExMeet = Get-CsTeamsMeetingPolicy -Identity Global | fl AllowExternalNonTrustedMeetingChat
if ($ExMeet.AllowExternalNonTrustedMeetingChat -eq $false) {
    $output = "External meeting chat is off. Control passed."
}
else {
    $output = "External meeting chat is on. Control failed."
}
$Report23.Add($ExMeet)
$Report23.Add($output)

#  Join the formatted report entries into a single string and save it to a text file.
$Report23 -join "`n" | Set-Content -Path "C:\Reports\M365AdminCenter.txt"

# Control 8.6.1: Ensure users can report security concerns in Teams.
# Create a new list to store the report data for this control.
$Report24 = [System.Collections.Generic.List[Object]]::new()

# Add a message specifying the control being implemented.
$Control24 = "Control 8.6.1: Ensure users can report security concerns in Teams."
$Report24.Add($Control24)

# Run the following PowerShell Command
$Teams =  Get-CsTeamsMessagingPolicy -Identity Global | fl AllowSecurityEndUserReporting
$Defender = Get-ReportSubmissionPolicy | fl Report*
$SOCAddress = Read-Host -Prompt "Please enter the SOC email address/Custom Email Address Reported Emails get sent to: "
if ($Teams.AllowSecurityEndUserReporting -eq $true -and 
    $Defender.ReportJunkToCustomizedAddress -eq $true -and 
    $Defender.ReportNotJunkToCustomizedAddress -eq $true -and 
    $Defender.ReportPhishToCustomizedAddress -eq $true -and 
    $Defender.ReportJunkAddresses -contains $SOCAddress -and 
    $Defender.ReportNotJunkAddresses -contains $SOCAddress -and 
    $Defender.ReportPhishAddresses -contains $SOCAddress -and 
    $Defender.ReportChatMessageEnabled -eq $false -and 
    $Defender.ReportChatMessageToCustomizedAddressEnabled -eq $true) {
    $output = "Users can report security concerns in Teams. Control passed."
}
else {
    $output = "Users cannot report security concerns in Teams. Control failed."
}
$Report24.Add($Teams)
$Report24.Add($Defender)
$Report24.Add($output)

#  Join the formatted report entries into a single string and save it to a text file.
$Report24 -join "`n" | Set-Content -Path "C:\Reports\M365AdminCenter.txt"

# Cleanup Process
# ----------------
#Removes the Custom Module path from the environment.
$env:PSModulePath = $env:PSModulePath -replace [regex]::Escape($customModulePath + ';'), ''

# Deletes the customModulePath directories and modules from the client Environment. Finished the cleanup process.
Remove-Item -Path $customModulePath -Recurse -Force
