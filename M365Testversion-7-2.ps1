#################################################################################################
# Author: Nicholas Fisher
# Date: February 4 2025
# Description of Script
# The provided PowerShell script is designed to support auditing and management of Microsoft 365
# environments based on Version 4.0 of the CIS M365 Benchmark. It defines a custom module path
# and installs essential PowerShell modules, including Az, PnP.PowerShell, AzureAD, MSOnline,
# and ExchangeOnlineManagement, to facilitate automated security assessments. The script aims
# to streamline the evaluation of M365 configurations against the CIS Benchmark, ensuring
# compliance with security best practices and enhancing the overall security posture.
#################################################################################################
#Script Setup Variables: (Other variables are defined in the script starting on line: 155)
#################################################################################################
$nugetExe = "$env:TEMP\nuget.exe"  # Path for temporary NuGet CLI
$nugetUrl = "https://dist.nuget.org/win-x86-commandline/latest/nuget.exe"  # Official NuGet download URL
$nugetSource = "https://api.nuget.org/v3/index.json"  # NuGet package repository URL
$packageName = "Microsoft.Extensions.Logging.Abstractions"  # The package we want to install
$packageVersion = "1.1.2"  # The specific version we need
$tempDir = "$env:TEMP\LoggingAbstractions"  # Temporary directory for storing the package
$originalLimit = $ExecutionContext.SessionState.MaxFunctionCount # Saves the clients default function limit
$NuGetExists = $false
$globalNuGet = Get-Command nuget -ErrorAction SilentlyContinue  # Check if NuGet is available globally
$existingSources = & "$nugetExe" sources list  # List registered package sources
$AssembleCheck = (Get-Package -Name $packageName -ErrorAction SilentlyContinue).Version  # Check if package exists
$dllPath = Get-ChildItem -Path "$tempDir" -Recurse -Filter "$packageName.dll" | Select-Object -ExpandProperty FullName
$customModulePath = ".\powershell\modules" # Define the custom module path
$outputPath = "C:\Reports"
$reportFile = Join-Path -Path $outputPath -ChildPath "M365AdminCenter.txt"

#################################################################################################
# Setting up the script environment:
#################################################################################################
$ExecutionContext.SessionState.Applications.MaximumFunctionCount = 40000 # Set the function limit to 40000

# Step 1: Check if NuGet CLI is available
if ($globalNuGet) {
    $NuGetExists = $true
    Write-Host "NuGet CLI is already installed: $($globalNuGet.Source)"
} elseif (Test-Path $nugetExe) {
    $NuGetExists = $true
    Write-Host "NuGet CLI found in temporary location: $nugetExe"
} else {
    Write-Host "NuGet CLI not found, downloading..."
    Invoke-WebRequest -Uri $nugetUrl -OutFile $nugetExe  # Download NuGet CLI if missing
}

# Step 2: Verify NuGet CLI Execution
if (Test-Path $nugetExe) {
    Write-Host "NuGet Version Check:"
    & "$nugetExe" help | Select-String "NuGet Version"  # Verify that NuGet CLI is working
} else {
    Write-Host "Error: NuGet CLI is missing!"
    exit 1  # Exit the script if NuGet CLI is not found
}

# Step 3: Ensure NuGet Source is Available
Write-Host "Checking NuGet sources..."
if ($existingSources -notmatch [regex]::Escape($nugetSource)) {
    Write-Host "Adding NuGet source: $nugetSource"
    & "$nugetExe" sources add -Name "nuget.org" -Source $nugetSource  # Register NuGet repository if missing
} else {
    Write-Host "NuGet source already exists."
}

# Convert version string to [System.Version] for accurate comparison
if (-not $AssembleCheck -or [System.Version]$AssembleCheck -ne [System.Version]$packageVersion) {
    Write-Host "Installing $packageName v$packageVersion..."
    
    # Ensure temporary package directory exists
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

    # Install the package using NuGet CLI
    & "$nugetExe" install $packageName -Version $packageVersion -OutputDirectory $tempDir -Source $nugetSource
}

if ($dllPath) {
    Write-Host "Loading assembly from: $dllPath"
    [System.Reflection.Assembly]::LoadFrom($dllPath) | Out-Null  # Dynamically load the assembly
    Write-Host "Package $packageName version $packageVersion loaded successfully!"
} else {
    Write-Host "Error: Package DLL not found!"
}


# Create the directory and subdirectory if they do not exist
if (-not (Test-Path -Path $customModulePath)) {
    New-Item -Path $customModulePath -ItemType Directory -Force
}

if (-not (Test-Path -Path $outputPath)) {
    New-Item -ItemType Directory -Path $outputPath -Force
}


# Install necessary modules
Save-Module -Name Az -Force -Path $customModulePath
Save-Module -Name PnP.PowerShell -Force -Path $customModulePath
Save-Module -Name AzureAD -Force -Path $customModulePath
Save-Module -Name MSOnline -Force -Path $customModulePath
Save-Module -Name ExchangeOnlineManagement -Force -Path $customModulePath
Save-Module -Name MicrosoftTeams -Force -Path $customModulePath
Save-Module -Name SharePointPnPPowerShellOnline -Force -Path $customModulePath
Save-Module -Name Az.Purview -Force -Path $customModulePath
Save-Module -Name Microsoft.Graph -Force -Path $customModulePath
#Adds custom module path to the environment variable PSModulePath.
$env:PSModulePath += ";$customModulePath"

# Find module directory, update modules path. 

# Import necessary modules
Import-Module -Name "$customModulePath\Az" -Force
Import-Module -Name "$customModulePath\PnP.PowerShell" -Force
Import-Module -Name "$customModulePath\AzureAD" -Force
Import-Module -Name "$customModulePath\MSOnline" -Force
Import-Module -Name "$customModulePath\ExchangeOnlineManagement" -Force
Import-Module -Name "$customModulePath\MicrosoftTeams" -Force
Import-Module -Name "$customModulePath\SharePointPnPPowerShellOnline" -Force
Import-Module -Name "$customModulePath\Az.Purview" -Force
Import-Module -Name "$customModulePath\Microsoft.Graph" -Force

# Check if the modules are imported successfully
if (-not (Get-Module -Name AzureAD)) { Write-Error "AzureAD module not imported" }
if (-not (Get-Module -Name MSOnline)) { Write-Error "MSOnline module not imported" }
if (-not (Get-Module -Name ExchangeOnlineManagement)) { Write-Error "ExchangeOnlineManagement module not imported" }
if (-not (Get-Module -Name MicrosoftTeams)) { Write-Error "MicrosoftTeams module not imported" }
if (-not (Get-Module -Name SharePointPnPPowerShellOnline)) { Write-Error "SharePointPnPPowerShellOnline module not imported" }
if (-not (Get-Module -Name Az.Purview)) { Write-Error "AzPurview module not imported" }

#  Connect to Account
# Connect to Azure AD with the necessary permissions for directory roles and user data.
Connect-AzAccount -TenantId $tenantID

# Connect to Exchange Online
Connect-ExchangeOnline

Connect-AzureAD 

# Connect to Microsoft Teams
Connect-MicrosoftTeams

Connect-AzureAD 
Connect-IPPSSession
Connect-SPOservice

# Connect to SharePoint Online
Connect-PnPOnline -Url "$($tenantURL)" -UseWebLogin

#################################################################################################
# Post Setup Variables:
#################################################################################################
$DirectoryRoles = Get-AzureADDirectoryRole # Get all directory roles in the Azure AD tenant
# Filter privileged roles
$PrivilegedRoles = $DirectoryRoles | Where-Object { 
    $_.DisplayName -like "*Administrator*" -or $_.DisplayName -eq "Global Reader" 
}
# Get the members of these roles
$RoleMembers = $PrivilegedRoles | ForEach-Object { 
    Get-AzureADDirectoryRoleMember -ObjectId $_.ObjectId 
} | Select-Object ObjectId -Unique
$PrivilegedUsers = $RoleMembers | ForEach-Object { 
    Get-AzureADUser -ObjectId $_.ObjectId | Select-Object UserPrincipalName, DisplayName, ObjectId 
}
$TrueCount = 0
$FalseCount = 0
$FalseUsers = @()
$PublicGroups = Get-AzureADGroup | Where-Object { $_.GroupTypes -contains "Unified" -and $_.Visibility -eq "Public" } # This retrieves all groups that are public.
# Retrieve all shared mailboxes in the tenant
# Get all mailboxes that are of type 'SharedMailbox'.
$MBX = Get-EXOMailbox -RecipientTypeDetails SharedMailbox
# Initialize lists to store UserPrincipalNames based on sign-in status
$SignInAllowedUsers = @()
$SignInBlockedUsers = @()
# Count the true and false values
$trueCount = $SignInAllowedUsers.Count
$falseCount = $SignInBlockedUsers.Count
#  Run the following PowerShell command to get the Hosted Connection Filter Policy
# Retrieve the Hosted Connection Filter Policy for the default identity and format the output to list the EnableSafeList property.
$FilterPolicy = Get-HostedConnectionFilterPolicy -Identity Default | Format-List EnableSafeList
# Retrieve all inbound anti-spam policies
$AntiSpamPolicies = Get-HostedContentFilterPolicy
# Initialize lists to store policies based on allowed sender domains status
$DefinedPolicies = @()
$UndefinedPolicies = @()
# Run the following PowerShell command:
$Auth = Get-OrganizationConfig | Select-Object Name, OAuth2ClientProfileEnabled
# Count the number of accounts with and without OAuth enabled
$PassCount = ($Auth | Where-Object { $_.OAuth2ClientProfileEnabled -eq $true }).Count
$FailCount = ($Auth | Where-Object { $_.OAuth2ClientProfileEnabled -eq $false }).Count
# List the accounts that do not have OAuth enabled
$FailedAccounts = $Auth | Where-Object { $_.OAuth2ClientProfileEnabled -eq $false } | Select-Object -ExpandProperty Name
$B2B = Get-SPOTenant | Select-Object -ExpandProperty EnableAzureADB2BIntegration # Get the Azure AD B2B integration status
$exShare = Get-SPOTenant | Select-Object -ExpandProperty SharingCapability # Get the external sharing capability
$LinkSharing = Get-SPOTenant | Select-Object -ExpandProperty DefaultSharingLinkType # Get the default sharing link type
$Control10 = "7.2.9: Ensure guest access to a site or OneDrive will expire automatically."
$UserExpire = $SPOTenant.ExternalUserExpirationRequired # Get the external user expiration required setting
$DaysExpire = [int]$SPOTenant.ExternalUserExpireInDays # Get the number of days before expiration
$SPOTenant = Get-SPOTenant # Get the SharePoint Online tenant settings
$LinkPermission = $SPOTenant.DefaultLinkPermission # Get the default sharing link permission
$InfectFiles = Get-SPOTenant | Select-Object DisallowInfectedFileDownload # Get the infected file download settings
$ApprovedServices = Get-CsTeamsClientConfiguration | Format-List AllowDropbox,AllowBox,AllowGoogleDrive,AllowShareFile,AllowEgnyte
# Convert the output to a string
$ApprovedServicesString = $ApprovedServices | Out-String # Convert the output to a string
$ChannelAddress = Get-CsTeamsClientConfiguration -Identity Global | Format-List AllowEmailIntoChannel # Get the channel email address settings
$FedUsers = Get-CsTenantFederationConfiguration | Select-Object -ExpandProperty AllowFederatedUsers # Get the federated users setting 
$AllowedDomains = Get-CsTenantFederationConfiguration | Select-Object -ExpandProperty AllowedDomains #  Get the allowed domains setting
$TeamsComms = Get-CsTenantFederationConfiguration | Select-Object -ExpandProperty AllowTeamsConsumer # Get the Teams consumer setting
$Inbound = Get-CsTenantFederationConfiguration | Select-Object -ExpandProperty AllowTeamsConsumerInbound # Get the Teams consumer inbound setting
$Anonjoin = Get-CsTeamsMeetingPolicy -Identity Global | Format-List AllowAnonymousUsersToJoinMeeting  # Get the anonymous users join meeting setting
$MeetingPolicy = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowAnonymousUsersToStartMeeting, AllowDialInUsersToStartMeeting # Get the meeting policy settings
$AnonDialer = $MeetingPolicy.AllowAnonymousUsersToStartMeeting # Get the anonymous users start meeting setting
$DialInUsers = $MeetingPolicy.AllowDialInUsersToStartMeeting # Get the dial-in users start meeting setting
$LobBypass = Get-CsTeamsMeetingPolicy -Identity Global | Format-List AutoAdmittedUsers # Get the lobby bypass setting
$BlockAnon = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object -Expand Property MeetingChatEnabledType # Get the meeting chat setting
$CoOrg = Get-CsTeamsMeetingPolicy -Identity Global | Format-List DesignatedPresenterRoleMode # Get the co-organizer setting
$ExMeet = Get-CsTeamsMeetingPolicy -Identity Global | Format-List AllowExternalNonTrustedMeetingChat # Get the external meeting chat setting
$Teams = Get-CsTeamsMessagingPolicy -Identity Global | Select-Object -ExpandProperty AllowSecurityEndUserReporting # Get the security end-user reporting setting
$Defender = Get-ReportSubmissionPolicy | Select-Object ReportJunkToCustomizedAddress, ReportNotJunkToCustomizedAddress, ReportPhishToCustomizedAddress, ReportJunkAddresses, ReportNotJunkAddresses, ReportPhishAddresses, ReportChatMessageEnabled, ReportChatMessageToCustomizedAddressEnabled # Get the Defender settings
$DlpPolicy = Get-DlpCompliancePolicy $DlpPolicy | Where-Object {$_.Workload -match "Teams"} | Format-Table Name,Mode,TeamsLocation* # Get the DLP policy for Teams

#################################################################################################
# Initialize the report and formated reports:
#################################################################################################
$Report = [System.Collections.Generic.List[Object]]::new()
$Report2 = [System.Collections.Generic.List[Object]]::new()
$Report3 = [System.Collections.Generic.List[Object]]::new()
$Report4 = [System.Collections.Generic.List[Object]]::new()
$FormattedReport4 = $Report4 | ForEach-Object { $_.ToString() } # Format the report entries for better readability. And to convert system objects to an appendable format
$Report5 = [System.Collections.Generic.List[Object]]::new()
$Report6 = [System.Collections.Generic.List[Object]]::new()
$Report7 = [System.Collections.Generic.List[Object]]::new()
$Report8 = [System.Collections.Generic.List[Object]]::new()
$Report9 = [System.Collections.Generic.List[Object]]::new()
$FormattedReport9 = $Report9 | ForEach-Object { $_.ToString() }
$Report10 = [System.Collections.Generic.List[Object]]::new()
$FormattedReport10 = $Report10 | ForEach-Object { $_.ToString() }
$Report11 = [System.Collections.Generic.List[Object]]::new()
$FormattedReport11 = $Report11 | ForEach-Object { $_.ToString() }
$Report12 = [System.Collections.Generic.List[Object]]::new()
$Report13 = [System.Collections.Generic.List[Object]]::new()
$FormattedReport13 = $Report13 | ForEach-Object { $_.ToString() }
$Report14 = [System.Collections.Generic.List[Object]]::new()
$FormattedReport14 = $Report14 | ForEach-Object { $_.ToString() }
$Report15 = [System.Collections.Generic.List[Object]]::new()
$Report16 = [System.Collections.Generic.List[Object]]::new()
$FormattedReport16 = $Report16 | ForEach-Object { $_.ToString() }
$Report17 = [System.Collections.Generic.List[Object]]::new()
$FormattedReport17 = $Report17 | ForEach-Object { $_.ToString() }
$Report18 = [System.Collections.Generic.List[Object]]::new()
$FormattedReport18 = $Report18 | ForEach-Object { $_.ToString() }
$Report19 = [System.Collections.Generic.List[Object]]::new()
$FormattedReport19 = $Report19 | ForEach-Object { $_.ToString() }
$Report20 = [System.Collections.Generic.List[Object]]::new()
$FormattedReport20 = $Report20 | ForEach-Object { $_.ToString() }
$Report21 = [System.Collections.Generic.List[Object]]::new()
$FormattedReport21 = $Report21 | ForEach-Object { $_.ToString() }
$Report22 = [System.Collections.Generic.List[Object]]::new()
$FormattedReport22 = $Report22 | ForEach-Object { $_.ToString() }
$Report23 = [System.Collections.Generic.List[Object]]::new()
$FormattedReport23 = $Report23 | ForEach-Object { $_.ToString() }
$Report24 = [System.Collections.Generic.List[Object]]::new()
$FormattedReport24 = $Report24 | ForEach-Object { $_.ToString() }
$Report25 = [System.Collections.Generic.List[Object]]::new()
$FormattedReport25 = $Report25 | ForEach-Object { $_.ToString() }
$Report26 = [System.Collections.Generic.List[Object]]::new()
$FormattedReport26 = $Report26 | ForEach-Object { $_.ToString() }

#################################################################################################
# Controls:
#################################################################################################
$Control = "Control: 1.1.4 Ensure administrative accounts use licenses with a reduced application footprint."
$Control2 = "Control: 2.1.13 Ensure the connection filter safe list is off."
$Control3 = "Control: 1.2.2 Ensure sign-in to shared mailboxes is blocked."
$Control4 = "Control: 1.2.1 Ensure that only organizationally managed/approved public groups exist."
$Control5 = "Control: 2.1.14 Ensure inbound anti-spam policies do not contain allowed domains."
$Control6 = "Control 6.5.1: Ensure Modern Authentication for Exchange Online is enabled."
$Control7 = "Control 7.2.2: Ensure SharePoint and OneDrive integration with Azure AD B2B is enabled."
$Control8 = "7.2.3: Ensure external content sharing is restricted."
$Control9 = "7.2.7: Ensure link sharing is restricted in SharePoint and OneDrive."
$Control10 = "7.2.9: Ensure guest access to a site or OneDrive will expire automatically."
$Control11 = "7.2.11: Ensure the SharePoint default sharing link permission is set."
$Control12 = "7.3.1: Ensure Office 365 SharePoint infected files are disallowed for download."
$Control13 = "8.1.1: Ensure external file sharing in Teams is enabled for only approved cloud storage services."
$Control14 = "8.1.2: Ensure users can't send emails to a channel email address."
$Control15 = "8.2.1: Ensure external domains are restricted in the Teams admin center."
$Control16 = "8.2.2: Ensure communication with unmanaged Teams users is disabled."
$Control17 = "8.2.3: Ensure external Teams users cannot initiate conversations."
$Control18 = "8.5.1: Ensure anonymous users can't join a meeting."
$Control19 = "8.5.2: Ensure anonymous users and dial-in callers can't start a meeting."
$Control20 = "8.5.3: Ensure only people in my org can bypass the lobby."
$Control21 = "8.5.5: Ensure meeting chat does not allow anonymous users."
$Control22 = "8.5.6: Ensure only organizers and co-organizers can present."
$Control23 = "8.5.8: Ensure external meeting chat is off."
$Control24 = "Control 8.6.1: Ensure users can report security concerns in Teams."
$Control25 = "Control: 2.1.10 Ensure DMARC Records for all Exchange Online domains are published."
$Control26 = "Control 3.2.2: Ensure DLP policies are enabled for Microsoft Teams."

#################################################################################################
# Edit Variables Below for each new client:
#################################################################################################
$tenantID = # Enter the Client's tenant ID
$tenantURL = # Enter the Client's SharePoint Tenant URL.
$domains = @("example.com", "example2.com")  # Replace with actual domains
$SOCAddress = # Please enter the Client's SOC email address/Custom Email Address Reported Emails get sent to:
#################################################################################################


#################################################################################################
# Script Begins Here:
#################################################################################################
# Retrieve detailed information for privileged users
if (-not (Get-Module -Name Az)) { Write-Error "Az module not imported" }
if (-not (Get-Module -Name PnP.PowerShell)) { Write-Error "PnP.PowerShell module not imported" }
if (-not (Get-Module -Name Microsoft.Graph)) { Write-Error "Microsoft.Graph module not imported" }
$PrivilegedUsers = $RoleMembers | ForEach-Object { 
    Get-AzureADUser -ObjectId $_.ObjectId | Select-Object UserPrincipalName, DisplayName, ObjectId 
}

# Add a message specifying the control being implemented.
$Report.Add($Control)

# Build the report for each user
foreach ($Admin in $PrivilegedUsers) {
    # Retrieve the licenses assigned to the user
    $License = (Get-AzureADUserLicenseDetail -ObjectId $Admin.ObjectId).SkuPartNumber -join ", "

    # Check if the user has an Entra Premium P1 or P2 license
    $HasP1P2License = $License -match "ENTERPRISEPREMIUM|ENTERPRISEPREMIUM_P2"

    # Increment the counters based on the license check
    if ($HasP1P2License) {
        $TrueCount++
    } else {
        $FalseCount++
        $FalseUsers += $Admin.UserPrincipalName
    }
}

# Add the summary to the report
$Report.Add("$TrueCount admins have the P1 or P2 License.")
if ($FalseCount -gt 0) {
    $FalseUsersList = $FalseUsers -join ", "
    $Report.Add("$FalseCount admins do not have the P1 or P2 License. The admins who do not are: $FalseUsersList")
}

# Join the formatted report entries into a single string and save it to a text file.
$Report -join "`n" | Add-Content -Path "C:\Reports\M365AdminCenter.txt"

# Add control message to the report
$Report4.Add($Control4)

# Add each public group to the report
$PublicGroups | ForEach-Object {
    $Report4.Add($_.DisplayName)
}

# Add the message to the report
$Report4.Add("Check on these in the appropriate discovery session.")


$FormattedReport4 -join "`n" | Add-Content -Path $reportFile

# Control 1.2.2: Ensure sign-in to shared mailboxes is blocked.
$Report3.Add($Control3)

# Loop through each shared mailbox and retrieve user details
$MBX | ForEach-Object {
    # Get user details for the shared mailbox using its ExternalDirectoryObjectId.
    $user = Get-MsolUser -ObjectId $_.ExternalDirectoryObjectId
    # Determine if sign-in is allowed based on the AccountEnabled property.
    if ($user.AccountEnabled -eq $true) {
        $SignInAllowedUsers += $user.UserPrincipalName
    } else {
        $SignInBlockedUsers += $user.UserPrincipalName
    }
}
# Add the summary to the report
if ($trueCount -gt 0) {
    $SignInAllowedUsersList = $SignInAllowedUsers -join ", "
    $Report3.Add("$trueCount shared mailboxes have sign-in allowed: $SignInAllowedUsersList")
} else {
    $Report3.Add("No shared mailboxes have sign-in allowed.")
}

if ($falseCount -gt 0) {
    $Report3.Add("$falseCount shared mailboxes have sign-in disabled.")
} else {
    $Report3.Add("No shared mailboxes have sign-in disabled.")
}

# Save the report to a text file
# Join the formatted report entries into a single string and save it to a text file.
$Report3 -join "`n" | Add-Content -Path "C:\Reports\Defender.txt"

# Control 2.1.10: Ensure DMARC Records for all Exchange Online domains are published.
$Report25.Add($Control25)


# Check DMARC records for each domain
foreach ($domain in $domains) {
    $dmarcRecord = Resolve-DnsName "_dmarc.$domain" -Type TXT -ErrorAction SilentlyContinue
    if ($dmarcRecord) {
        $dmarcValue = $dmarcRecord | Select-Object -ExpandProperty Strings
        if ($dmarcValue -match "v=DMARC1" -and $dmarcValue -match "p=(quarantine|reject)" -and $dmarcValue -match "pct=100" -and $dmarcValue -match "rua=mailto:" -and $dmarcValue -match "ruf=mailto:") {
            $Report25.Add("DMARC record for ${domain}: ${dmarcValue} - Control passed.")
        } else {
            $Report25.Add("DMARC record for ${domain}: $dmarcValue - Control failed. Missing required flags.")
        }
    } else {
        $Report25.Add("No DMARC record found for $domain - Control failed.")
    }
}

# Save the report to a text file
$FormattedReport25 -join "`n" | Add-Content -Path "C:\Reports\Defender.txt"

# Control 2.1.13: Ensure the connection filter safe list is off.
$Report2.Add($Control2)

#  Ensure EnableSafeList is False
# Check if the EnableSafeList property is set to False and add the result to the report.
if ($FilterPolicy.EnableSafeList -eq $false) {
    $Report2.Add("EnableSafeList is False, Control Passed.")
} else {
    $Report2.Add("EnableSafeList is not False, Control Failed.")
}

#Append append it to the text file.
$Report2 -join "`n" | Add-Content -Path $reportFile

# Control 2.1.14: Ensure inbound anti-spam policies do not contain allowed domains.
$Report5.Add($Control5)

# Loop through each anti-spam policy and check for allowed sender domains
foreach ($Policy in $AntiSpamPolicies) {
    $AllowedSenderDomains = $Policy.AllowedSenderDomains -join ", "

    # Add the policy details to the appropriate list
    if ($AllowedSenderDomains) {
        $DefinedPolicies += $Policy.Identity
    } else {
        $UndefinedPolicies += $Policy.Identity
    }
}

# Add the summary to the report
if ($UndefinedPolicies.Count -gt 0) {
    $UndefinedPoliciesList = $UndefinedPolicies -join ", "
    $Report5.Add("The following domains inbound anti-spam policies are undefined: $UndefinedPoliciesList. Domains pass.")
} else {
    $Report5.Add("No inbound anti-spam policies are undefined. All domains pass.")
}

if ($DefinedPolicies.Count -gt 0) {
    $DefinedPoliciesList = $DefinedPolicies -join ", "
    $Report5.Add("The following domains inbound anti-spam policies are defined: $DefinedPoliciesList. Domains failed.")
} else {
    $Report5.Add("No inbound anti-spam policies are defined. All domains pass.")
}

# Save the report to a text file
# Join the formatted report entries into a single string and save it to a text file.
$Report5 -join "`n" | Add-Content -Path "C:\Reports\Defender.txt"

# Control 3.2.2: Ensure DLP policies are enabled for Microsoft Teams 
$Report26.Add($Control26)
$Report26.Add($DlpPolicy)
$Report26.Add("Review Guidelines on how to assess in work program.")

$FormattedReport26 -join "`n" | Add-Content -Path $reportFile


# Control 6.5.1: Ensure Modern Authentication for Exchange Online is enabled
$Report6.Add($Control6)

# Add the authentication configuration details to the report
$Report6.Add("$PassCount accounts have modern authentication enabled.")
if ($FailCount -gt 0) {
    $FailedAccountsList = $FailedAccounts -join ", "
    $Report6.Add("$FailCount accounts do not have modern authentication enabled. Please enable it on the following accounts: $FailedAccountsList")
} else {
    $Report6.Add("All accounts have modern authentication enabled.")
}

# Save the report to a text file
# Join the formatted report entries into a single string and save it to a text file.
$Report6 -join "`n" | Add-Content -Path "C:\Reports\Defender.txt"

# Control 7.2.2: Ensure SharePoint and OneDrive integration with Azure AD B2B is enabled.
$Report7.Add($Control7)

if ($B2B -eq $false) {
    $output = "Azure AD B2B integration is not enabled between SharePoint and OneDrive. Control failed."
}
else {
    $output = "Azure AD B2B integration is enabled between SharePoint and OneDrive. Control passed."
}
$Report7.Add("EnableAzureADB2BIntegration: $B2B")
$Report7.Add($output)

#  Join the formatted report entries into a single string and save it to a text file.

$Report7 -join "`n" | Add-Content -Path $reportFile

#Control 7.2.3: Ensure external content sharing is restricted.
$Report8.Add($Control8)

#  Run the following Powershell Command
if ($exShare -eq "ExternalUserSharingOnly" -or $exShare -eq "ExistingExternalUserSharingOnly" -or $exShare -eq "Disabled") {
    $output = "External content sharing is restricted. Control passed."
}
else {
    $output = "External content sharing is not restricted. Control failed."
}
$Report8.Add("SharingCapability: $exShare")
$Report8.Add($output)

#  Join the formatted report entries into a single string and save it to a text file.
$Report8 -join "`n" | Add-Content -Path $reportFile

# Control 7.2.7: Ensure link sharing is restricted in SharePoint and OneDrive.
$Report9.Add($Control9)

# Run the following PowerShell Commands
if ($LinkSharing -eq "Direct") {
    $output = "Link sharing is restricted. Control passed."
} else {
    $output = "Link sharing is not restricted. Control failed."
}
$Report9.Add("DefaultSharingLinkType: $LinkSharing")
$Report9.Add($output)

# Join the formatted report entries into a single string and save it to a text file.
$FormattedReport9 -join "`n" | Add-Content -Path $reportFile

# Control 7.2.9: Ensure guest access to a site or OneDrive will expire automatically.
$Report10.Add($Control10)

if ($UserExpire -eq $true) {
    $output = "Guest access will expire automatically. Control passed."
} else {
    $output = "Guest access will not expire automatically. Control failed."
}

if ($DaysExpire -le 30) {
    $output2 = "Guest access will expire in 30 or less days. Control passed."
} else {
    $output2 = "Guest access will not expire in 30 days. Control failed."
}

$Report10.Add("ExternalUserExpirationRequired: $UserExpire")
$Report10.Add("ExternalUserExpireInDays: $DaysExpire")
$Report10.Add($output)
$Report10.Add($output2)

# Join the formatted report entries into a single string and save it to a text file.
$FormattedReport10 -join "`n" | Add-Content -Path $reportFile

# Control 7.2.11: Ensure the SharePoint default sharing link permission is set.
$Report11.Add($Control11)

# Run the following PowerShell Commands
if ($LinkPermission -eq "View") {
    $output = "Default sharing link permission is set to View. Control passed."
} else {
    $output = "Default sharing link permission is not set to View. Control failed."
}

$Report11.Add("DefaultLinkPermission: $LinkPermission")
$Report11.Add($output)

# Join the formatted report entries into a single string and save it to a text file.
$FormattedReport11 -join "`n" | Add-Content -Path $reportFile

# Control 7.3.1: Ensure Office 365 SharePoint infected files are disallowed for download. 
$Report12.Add($Control12)

#  Run the following Powershell Commands
if ($InfectFiles.DisallowInfectedFileDownload -eq $true) {
    $output = "Infected files are disallowed for download. Control passed."
}
else {
    $output = "Infected files are allowed for download. Control failed."
}
$Report12.Add($InfectFiles)
$Report12.Add($output)

#  Join the formatted report entries into a single string and save it to a text file.
$Report12 -join "`n" | Add-Content -Path $reportFile

# Control 8.1.1: Ensure external file sharing in Teams is enabled for only approved cloud storage services.
$Report13.Add($Control13)

# Append the control message and the output to the text file
$Report13.Add($ApprovedServicesString)
$Report13.Add("Check these in discovery session to ensure compliance.")
$FormattedReport13 -join "`n" | Add-Content -Path $reportFile


# Control 8.1.2: Ensure users can't send emails to a channel email address.
$Report14.Add($Control14)
if ($ChannelAddress.AllowEmailIntoChannel -eq $false) {
    $output = "Users can't send emails to a channel email address. Control passed."
}
else {
    $output = "Users can send emails to a channel email address. Control failed."
}
$Report14.Add("AllowEmailIntoChannel:$ChannelAddress")
$Report14.Add($output)

#  Join the formatted report entries into a single string and save it to a text file.
$FormattedReport14 -join "`n" | Add-Content -Path $reportFile

# Control 8.2.1: Ensure external domains are restricted in the Teams admin center.
$Report15.Add($Control15)

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
$Report15 -join "`n" | Add-Content -Path $reportFile

# Control 8.2.2: Ensure communication with unmanaged Teams users is disabled.
$Report16.Add($Control16)

if ($TeamsComms -eq $false) {
    $output = "Communication with unmanaged Teams users is disabled. Control passed."
} else {
    $output = "Communication with unmanaged Teams users is enabled. Control failed."
}

$Report16.Add("AllowTeamsConsumer: $TeamsComms")
$Report16.Add($output)

# Join the formatted report entries into a single string and save it to a text file.
$FormattedReport16 -join "`n" | Add-Content -Path $reportFile

# Control 8.2.3: Ensure external Teams users cannot initiate conversations.
$Report17.Add($Control17)

if ($Inbound -eq $false) {
    $output = "External Teams users cannot initiate conversations. Control passed."
} else {
    $output = "External Teams users can initiate conversations. Control failed."
}

$Report17.Add("AllowTeamsConsumerInbound: $Inbound")
$Report17.Add($output)

# Join the formatted report entries into a single string and save it to a text file.
$FormattedReport17 -join "`n" | Add-Content -Path $reportFile

# Control 8.5.1: Ensure anonymous users can't join a meeting.
$Report18.Add($Control18)

if ($Anonjoin.AllowAnonymousUsersToJoinMeeting -eq $false) {
    $output = "Anonymous users can't join a meeting. Control passed."
}
else {
    $output = "Anonymous users can join a meeting. Control failed."
}
$Report18.Add("AllowAnonymousUsersToJoinMeeting: $Anonjoin")
$Report18.Add($output)

#  Join the formatted report entries into a single string and save it to a text file.
$FormattedReport18 -join "`n" | Add-Content -Path $reportFile

# Control 8.5.2: Ensure anonymous users and dial-in callers can't start a meeting.
$Report19.Add($Control19)

if ($AnonDialer -eq $false -and $DialInUsers -eq $false) {
    $output = "Anonymous users and dial-in callers can't start a meeting. Control passed."
} else {
    $output = "Anonymous users and dial-in callers can start a meeting. Control failed."
}

$Report19.Add("AllowAnonymousUsersToStartMeeting: $AnonDialer")
$Report19.Add("AllowDialInUsersToStartMeeting: $DialInUsers")
$Report19.Add($output)

# Join the formatted report entries into a single string and save it to a text file.
$FormattedReport19 -join "`n" | Add-Content -Path $reportFile

# Control 8.5.3: Ensure only people in my org can bypass the lobby.
$Report20.Add($Control20)

if ($LobBypass.AutoAdmittedUsers -eq "EveryoneInCompanyExcludingGuests") {
    $output = "Only people in my org can bypass the lobby. Control passed."
}
else {
    $output = "People outside my org can bypass the lobby. Control failed."
}
$Report20.Add("AutoAdmittedUsers: $LobBypass")
$Report20.Add($output)

#  Join the formatted report entries into a single string and save it to a text file.
$FormattedReport20 -join "`n" | Add-Content -Path $reportFile

# Control 8.5.5: Ensure meeting chat does not allow anonymous users.
$Report21.Add($Control21)

if ($BlockAnon -eq "DisabledForAnonymousUsers" -or $BlockAnon -eq "EnabledExceptAnonymous") {
    $output = "Meeting chat does not allow anonymous users. Control passed."
} else {
    $output = "Meeting chat allows anonymous users. Control failed."
}

$Report21.Add("MeetingChatEnabledType: $BlockAnon")
$Report21.Add($output)

# Join the formatted report entries into a single string and save it to a text file.
$FormattedReport21 -join "`n" | Add-Content -Path $reportFile

#Control 8.5.6: Ensure only organizers and co-organizers can present.
$Report22.Add($Control22)

if ($CoOrg.DesignatedPresenterRoleMode -eq "OrganizerOnly" -or $CoOrg.DesignatedPresenterRoleMode -eq "CoOrganizerAndOrganizer" -or $CoOrg.DesignatedPresenterRoleMode -eq "OrganizerOnlyUserOverride") {
    $output = "Only organizers and co-organizers can present. Control passed."
}
else {
    $output = "Other participants can present. Control failed."
}
$Report22.Add("DesignatedPresenterRoleMode: $CoOrg")
$Report22.Add($output)

#  Join the formatted report entries into a single string and save it to a text file.
$FormattedReport22 -join "`n" | Add-Content -Path $reportFile

# Control 8.5.8: Ensure external meeting chat is off.
$Report23.Add($Control23)

if ($ExMeet.AllowExternalNonTrustedMeetingChat -eq $false) {
    $output = "External meeting chat is off. Control passed."
}
else {
    $output = "External meeting chat is on. Control failed."
}
$Report23.Add("AllowExternalNonTrustedMeetingChat: $ExMeet")
$Report23.Add($output)

#  Join the formatted report entries into a single string and save it to a text file.
$FormattedReport23 -join "`n" | Add-Content -Path $reportFile

# Control 8.6.1: Ensure users can report security concerns in Teams.
$Report24.Add($Control24)

if ($Teams -eq $true -and 
    $Defender.ReportJunkToCustomizedAddress -eq $true -and 
    $Defender.ReportNotJunkToCustomizedAddress -eq $true -and 
    $Defender.ReportPhishToCustomizedAddress -eq $true -and 
    $Defender.ReportJunkAddresses -contains $SOCAddress -and 
    $Defender.ReportNotJunkAddresses -contains $SOCAddress -and 
    $Defender.ReportPhishAddresses -contains $SOCAddress -and 
    $Defender.ReportChatMessageEnabled -eq $false -and 
    $Defender.ReportChatMessageToCustomizedAddressEnabled -eq $true) {
    $output = "Users can report security concerns in Teams. Control passed."
} else {
    $output = "Users cannot report security concerns in Teams. Control failed."
}

$Report24.Add("AllowSecurityEndUserReporting: $Teams")
$Report24.Add("ReportJunkToCustomizedAddress: $($Defender.ReportJunkToCustomizedAddress)")
$Report24.Add("ReportNotJunkToCustomizedAddress: $($Defender.ReportNotJunkToCustomizedAddress)")
$Report24.Add("ReportPhishToCustomizedAddress: $($Defender.ReportPhishToCustomizedAddress)")
$Report24.Add("ReportJunkAddresses: $($Defender.ReportJunkAddresses -join ', ')")
$Report24.Add("ReportNotJunkAddresses: $($Defender.ReportNotJunkAddresses -join ', ')")
$Report24.Add("ReportPhishAddresses: $($Defender.ReportPhishAddresses -join ', ')")
$Report24.Add("ReportChatMessageEnabled: $($Defender.ReportChatMessageEnabled)")
$Report24.Add("ReportChatMessageToCustomizedAddressEnabled: $($Defender.ReportChatMessageToCustomizedAddressEnabled)")
$Report24.Add($output)

# Join the formatted report entries into a single string and save it to a text file.
$FormattedReport24 -join "`n" | Add-Content -Path $reportFile

# Cleanup Process
# ----------------
#Removes the Custom Module path from the environment.
$env:PSModulePath = $env:PSModulePath -replace [regex]::Escape($customModulePath + ';'), ''

# Deletes the customModulePath directories and modules from the client Environment. Finished the cleanup process.
Remove-Item -Path $customModulePath -Recurse -Force

$ExecutionContext.SessionState.MaxFunctionCount = $originalLimit

# Unloads the Assembly (Free Up Memory)
Write-Host "Unloading the assembly..."
[System.GC]::Collect()  # Force garbage collection
[System.GC]::WaitForPendingFinalizers()

# Unregisters NuGet Source (If It Was Added)
if ($addedNuGetSource) {
    Write-Host "Removing temporary NuGet source: $nugetSource"
    & "$nugetExe" sources remove -Name "nuget.org"
}

# Cleansup (Remove NuGet CLI if it was downloaded in this session)
if (-Not $NuGetExists) {
    Write-Host "Cleaning up: Removing temporary NuGet CLI..."
    Remove-Item -Path $nugetExe -Force -ErrorAction SilentlyContinue
}

# Cleanups the Downloaded Package Files
Write-Host "Cleaning up: Removing temporary package files..."
Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Script execution complete."
