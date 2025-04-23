$tempPath = $env:windir + "\Temp"
$resultsFile = Join-Path -Path $tempPath -ChildPath "SecurityCheckResults.txt"

if (-not (Test-Path -Path $resultsFile)) {
    New-Item -ItemType File -Path $resultsFile -Force
}

$auditpolFile = Join-Path -Path $tempPath -ChildPath "auditpol.txt"

$results = @()
$totalChecks = 0
$passedChecks = 0

# Add after your initial variables
$checkedPolicies = @{}

# Create a mapping dictionary
$policyNameMapping = @{
    "Remove all unnecessary programs and applications" = "RemoveUnneededProgramsApps"
    "Disable Telnet service" = "DisableUnneededServicesTelnetTFTPRemoteRegistry"
    "Disable TFTP service" = "DisableUnneededServicesTelnetTFTPRemoteRegistry"
    "Disable Remote Registry service" = "DisableUnneededServicesTelnetTFTPRemoteRegistry"
    "Configure standard user accounts" = "ConfigureStandardUserAccountsPerAccessControlFramework"
    "Restrict standard users from underlying OS configs" = "RestrictStandardUsersFromUnderlyingOsConfigs"
    "Disable USB ports for standard users" = "DisableAllUsbPortsForStandardUsersUnlessNeeded"
    "Disable CD-ROM drives for standard users" = "DisableCdRomDrivesForStandardUsers"
    "Configure administrator accounts" = "ConfigureAdminAccountsPerAccessControlFramework"
    "Disable 'Autorun' capability for all external media" = "DisableAutorunForExternalMedia"
    "Security Option: Interactive Logon - Do not display last user name" = "SecurityInteractiveLogonDontDisplayLastUserName"
    "Enable and configure Windows firewall" = "EnableWindowsFirewallForNeededProgramsPortsProtocols"
    "Deploy and configure security software" = "DeploySecuritySoftwareAntiVirusWhitelistingPerOpsMaintFramework"
    "Configure auditing and logging" = "ConfigureAuditingLoggingPerOpsMaintFramework"
    "Configure password policies" = "ConfigurePasswordPoliciesPerAccessControlFramework"
    "Rename built-in administrator account" = "RenameBuiltInAdminAccounts"
    "Disable built-in guest account" = "DisableBuiltInGuestAccount"
    "Configure non-human service accounts to disallow interactive logins" = "DisableInteractiveLoginsForNonHumanServiceAccounts"
    "Set the 'Limit local account use of blank passwords to console logon only' right to Enable" = "LimitBlankPasswordsForConsoleLogonEnable"
    "Set UAC to highest level" = "TurnOnUacToHighestLevelAlwaysNotify"
    "Set 'Admin Approval Mode for the built-in Administrator account' to Enabled" = "AdminApprovalModeForBuiltInAdminAccountEnabled"
    "Set 'Behavior of the elevation prompt for standard users' to 'Prompt for credentials on the secure desktop'" = "ElevationPromptForStandardUsersCredentialsOnSecureDesktop"
    "Set 'Detect application installations and prompt for elevation' to Enabled" = "DetectAppInstallsPromptForElevationEnabled"
    "Set 'Only elevate UIAccess applications that are installed in secure locations' to Enabled" = "ElevateUIAccessAppsInSecureLocationsEnabled"
    "Set 'Virtualize file and registry write failures to per-user locations' to Enabled" = "VirtualizeFileRegistryWritesToPerUserLocationsEnabled"
    "Set the 'Do not require CTRL+ALT+DEL' policy setting to Disabled" = "DontRequireCtrlAltDelDisabled"
    "Configure the logon message title and text for users attempting to log on" = "MessageTitleForLogonAttemptsDisplayWarningBanner"
    "Set 'Message Text for users attempting to log on'" = "SecurityInteractiveLogonMessageTextForLogonAttempts"
    "Disable LAN Manager hash use and enable NTLMv2" = "DisableLanManagerHashIfPossibleEnableNtlmv2"
    "Do not store LAN Manager hash on next password change" = "DontStoreLanManagerHashOnNextPasswordChangeDisabled"
    "Set the 'Do not allow anonymous enumeration of SAM accounts and shares' policy setting to Enabled" = "DontAllowAnonymousEnumerationOfSamAcctsSharesEnabled"
    "Remove the 'Act as part of the operating system' right from all accounts" = "RemoveActAsOsRightFromAccountsGroupsUnlessNeeded"
    "Remove the 'Debug programs' right from all accounts unless necessary" = "RemoveDebugProgramsRightFromAccountsGroupsUnlessNeeded"
    "Restrict 'Access this computer from the network' right" = "RemoveAccessThisComputerFromWorkstationsHmisUnlessNeeded"
    "Restrict the 'Force Shutdown from a Remote System' policy to administrators" = "RestrictForceShutdownToAdminGroupUsersWithNeed"
    "Set the 'Recovery Console: Allow automatic administrative logon' policy setting to Disabled" = "RecoveryConsoleDisableAutomaticAdminLogon"
    "Configure NTP" = "ConfigureNtp"
    "Disable unused network adapters" = "DisableUnusedNetworkAdapters"
    "Configure logon banner" = "LoginBanner"
    "Check network security settings" = "SecurityMsNetworkClientEnableDigitallySignedCommsAlways"
    "Network Security - Digital Signing and NTLM SSP Settings" = "SecurityNetworkSecuritySetMinSessionSecurityForNtlmSspClients"
    "Check device installation settings" = "DeviceInstallAllowAdminsToOverrideInstallRestrictions"
    "Check removable storage access" = "RemovableStorageDenyAllRemovableStorageAccess"
    "Check network settings" = "DnsClientEnableTurnOffMulticastNameResolution"
    "Check remote assistance settings" = "RemoteAssistanceDisableConfigureOfferRemoteAssistance"
    "Check PowerShell settings" = "WindowsPowerShellTurnOnModuleLogging"
    "Check PowerShell script block logging" = "WindowsPowerShellTurnOnPowerShellScriptBlockLogging"
    "Check PowerShell transcription" = "WindowsPowerShellTurnOnPowerShellTranscription"
    "Check PowerShell lockdown policy" = "EnvironmentVariableSectionDefineValueForPSLockdownPolicyRestricted"
    "Check IPv6 settings" = "DisableIpv6ForAllAdaptors"
    "Check NetBIOS settings" = "DisableNetbiosOverTcpIpForAllNetworkAdaptorsThatHaveIpEnabled"
    "Check SMB settings" = "DisableSmbVersion1"
    "Check internet resource contact" = "ComputersWillBeConfiguredToNotContactInternetResources"
    "Check machine account password settings" = "DisableRefuseMachineAccountPasswordChanges"
    "Check secure channel settings" = "EnableDigitallyEncryptOrSignSecureChannelDataAlways"
    "Check session key settings" = "EnableRequireStrongSessionKey"
    "Check system shutdown settings" = "DisableAllowSystemToBeShutDownWithoutHavingToLogOn"
    "Check elevation prompt behavior" = "DenyBehaviorOfTheElevationPromptForStandardUsers"
    "Check font provider settings" = "DisableEnableFontProviders"
    "Check guest logon settings" = "DisableEnableInsecureGuestLogons"
    "Check mapper I/O settings" = "DisableTurnOnMapperIoLltddioDriver"
    "Check responder driver settings" = "DisableTurnOnResponderRspndrDriver"
    "Check group policy refresh settings" = "DisableTurnOffBackgroundRefreshOfGroupPolicy"
    "Check print driver download settings" = "EnableTurnOffDownloadingOfPrintDriversOverHttp"
    "Check internet connection wizard settings" = "EnableTurnOffInternetConnectionWizardIfUrlReferringMicrosoftCom"
    "Check internet download settings" = "EnableTurnOffInternetDownloadForWebPublishingOnlineOrdering"
    "Check HTTP printing settings" = "EnableTurnOffPrintingOverHttp"
    "Check point and print restrictions" = "EnablePointAndPrintRestrictionsWhenInstallingNewDrivers"
    "Check point and print driver update restrictions" = "EnablePointAndPrintRestrictionsWhenUpdatingDrivers"
    "Check printer driver installation restrictions" = "EnableLimitPrintDriverInstallationToAdministrators"
    "Check device driver installation restrictions" = "EnableDevicesPreventUsersFromInstallingPrinterDrivers"
    "Check registration wizard settings" = "EnableTurnOffRegistrationIfUrlReferringToMicrosoftCom"
    "Check search companion settings" = "EnableTurnOffSearchCompanionContentFileUpdates"
    "Check picture ordering settings" = "EnableTurnOffTheOrderPrintsPictureTask"
    "Check web publishing settings" = "EnableTurnOffThePublishToWebTaskForFilesAndFolders"
    "Check Windows Messenger settings" = "EnableTurnOffTheWindowsMessengerCustomerExpImprovementProgram"
    "Check Windows Customer Experience settings" = "EnableTurnOffWindowsCustomerExpImprovementProgram"
    "Check Windows Error Reporting settings" = "EnableTurnOffWindowsErrorReporting"
    "Check device authentication settings" = "EnableSupportDeviceAuthenticationUsingCertificate"
    "Check app notifications settings" = "EnableTurnOffAppNotificationsOnTheLockScreen"
    "Check picture password settings" = "EnableTurnOffPicturePasswordSignIn"
    "Check PIN sign-in settings" = "DisableTurnOnConveniencePinSignIn"
    "Check Windows NTP client settings" = "EnableWindowsNtpClient"
    "Check app data sharing settings" = "DisableAllowAWindowsAppToShareApplicationData"
    "Check Microsoft account settings" = "EnableAllowMicrosoftAccountsToBeOptional"
    "Check password reveal settings" = "EnableDoNotDisplayThePasswordRevealButton"
    "Check COM port redirection settings" = "EnableDoNotAllowComPortRedirection"
    "Check RDP password prompt settings" = "EnableAlwaysPromptClientForPasswordUponConnection"
    "Check device redirection settings" = "DoNotAllowSupportedPlugAndPlayDeviceRedirection"
    "Check RPC communication settings" = "EnableRequireSecureRpcCommunication"
    "Check temporary folder deletion settings" = "DisableDoNotDeleteTempFoldersUponExit"
    "Check temporary folder session settings" = "EnableDoNotUseTemporaryFoldersPerSession"
    "Check Microsoft Maps settings" = "DisableJoinMicrosoftMaps"
    "Check Windows Ink Workspace settings" = "DisableAllowSuggestedAppsInWindowsInkWorkspace"
    "Check Windows Ink settings" = "DisableAllowWindowsInkWorkspace"
    "Check codec download settings" = "EnablePreventCodecDownload"
    "Check drive redirection settings" = "VerifyDriveRedirectionIsNotConfiguredByDefault"
    "Check RDP password saving settings" = "EnableDoNotAllowPasswordsToBeSavedInGpoForRemoteDesktop"
    "Check RDP session time limit settings" = "EnableSetTimeLimitForActiveButIdleRemoteDesktopSessions15Mins"
    "Check Recycle Bin settings" = "RecycleBinSettingFilesDeletedAfter7DaysRestrictRecycleBinStorage"
    "Check administrator enumeration settings" = "DisableEnumerateAdministratorAccountsOnElevation"
    "Check Internet Explorer settings" = "DisableInternetExplorerOnUnnecessaryWorkstationsEtc"
    "Check SmartScreen settings" = "ActivateSmartScreenViaMicrosoftDefenderEtcManagedByGroupPolicy"
    "Check FTP settings" = "DisableAnonymousFtpFileShareOnWindowsMachine"
    "Check Windows Store settings" = "DisableWindowsStoreOnUnnecessaryWorkstationsEtc"  }

# Modify the Add-Result function to prevent duplicates
function Add-Result {
    param (
        [string]$Description,
        [string]$Status,
        [string]$Details = ""
    )
    
    # Skip if this policy has already been checked
    if ($checkedPolicies.ContainsKey($Description)) {
        return
    }
    
    $global:totalChecks++
    if ($Status -eq "Applied") {
        $global:passedChecks++
    }
    
    $policyName = if ($policyNameMapping.ContainsKey($Description)) {
        $policyNameMapping[$Description]
    } else {
        $Description
    }
    
    $result = [PSCustomObject]@{
        Description = $policyName
        Status = $Status
        Details = $Details
    }
    
    $global:results += $result
    $checkedPolicies[$Description] = $true
}

# Function to check registry settings
function Check-RegistrySetting {
    param (
        [string]$Path,
        [string]$Name,
        [object]$ExpectedValue,
        [string]$Description
    )
    
    try {
        if (Test-Path $Path) {
            $actualValue = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
            
            if ($null -eq $actualValue) {
                Add-Result -Description $Description -Status "Not Found" -Details "Registry value not found"
            }
            else {
                $details = "Expected: $ExpectedValue, Found: $actualValue"
                
                if ($actualValue -eq $ExpectedValue) {
                    Add-Result -Description $Description -Status "Applied" -Details $details
                }
                else {
                    Add-Result -Description $Description -Status "Not Applied" -Details $details
                }
            }
        }
        else {
            Add-Result -Description $Description -Status "Not Found" -Details "Registry path not found"
        }
    }
    catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking registry setting: $_"
    }
}

function Check-NetworkSecuritySettings {
    param (
        [string]$Description
    )
    
    try {
        # 1. Check IPv6 Settings
        $adapters = Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
        $allDisabled = $true
        foreach ($adapter in $adapters) {
            if ($adapter.Enabled) {
                $allDisabled = $false
                break
            }
        }
        Add-Result -Description "DisableIpv6ForAllAdaptors" `
            -Status $(if ($allDisabled) { "Applied" } else { "Not Applied" }) `
            -Details "IPv6 status on network adapters"

        # 2. Check Windows Firewall
        $firewallProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        $firewallEnabled = $true
        foreach ($profile in $firewallProfiles) {
            if (-not $profile.Enabled) {
                $firewallEnabled = $false
                break
            }
        }
        Add-Result -Description "EnableWindowsFirewallForNeededProgramsPortsProtocols" `
            -Status $(if ($firewallEnabled) { "Applied" } else { "Not Applied" }) `
            -Details "Windows Firewall status across all profiles"

        # 3. Check NetBIOS Settings
        $adaptersWithNetBIOS = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | 
            Where-Object { $_.IPEnabled -eq $true -and $_.TcpipNetbiosOptions -ne 2 }
        Add-Result -Description "DisableNetbiosOverTcpIpForAllNetworkAdaptorsThatHaveIpEnabled" `
            -Status $(if ($null -eq $adaptersWithNetBIOS) { "Applied" } else { "Not Applied" }) `
            -Details "NetBIOS over TCP/IP status"

        # 4. Check Digital Signing Settings
        Check-RegistrySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
            -Name "RequireSecuritySignature" `
            -ExpectedValue 1 `
            -Description "SecurityMsNetworkClientEnableDigitallySignedCommsAlways"

        # 5. Check DNS Client Settings
        Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
            -Name "EnableMulticast" `
            -ExpectedValue 0 `
            -Description "DnsClientEnableTurnOffMulticastNameResolution"

        # 6. Check Unused Network Adapters
        $disabledAdapters = Get-NetAdapter -ErrorAction SilentlyContinue | 
            Where-Object { $_.Status -eq 'Disabled' }
        Add-Result -Description "DisableUnusedNetworkAdapters" `
            -Status "Manual Check Required" `
            -Details "Manual verification needed for unused network adapters"

        # 7. Check Secure Channel Settings
        Check-RegistrySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
            -Name "SignSecureChannel" `
            -ExpectedValue 1 `
            -Description "EnableDigitallyEncryptOrSignSecureChannelDataAlways"

        # 8. Check Point and Print Restrictions
        Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" `
            -Name "RestrictDriverInstallationToAdministrators" `
            -ExpectedValue 1 `
            -Description "EnablePointAndPrintRestrictionsWhenInstallingNewDrivers"
    }
    catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking network security settings: $_"
    }
}

function Check-RemoteAccessSecuritySettings {
    param (
        [string]$Description
    )
    
    try {
        # 1. Check Remote Desktop Device Redirection
        Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
            -Name "fDisablePNPRedir" `
            -ExpectedValue 1 `
            -Description "DoNotAllowSupportedPlugAndPlayDeviceRedirection"

        # 2. Check Remote Desktop Password Prompt
        Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
            -Name "fPromptForPassword" `
            -ExpectedValue 1 `
            -Description "EnableAlwaysPromptClientForPasswordUponConnection"

        # 3. Check COM Port Redirection
        Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
            -Name "fDisableCcm" `
            -ExpectedValue 1 `
            -Description "EnableDoNotAllowComPortRedirection"

        # 4. Check RDP Password Saving
        Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
            -Name "DisablePasswordSaving" `
            -ExpectedValue 1 `
            -Description "EnableDoNotAllowPasswordsToBeSavedInGpoForRemoteDesktop"

        # 5. Check RPC Communication
        Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
            -Name "fEncryptRPCTraffic" `
            -ExpectedValue 1 `
            -Description "EnableRequireSecureRpcCommunication"

        # 6. Check RDP Session Time Limit
        Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
            -Name "MaxIdleTime" `
            -ExpectedValue 900000 `  # 15 minutes in milliseconds
            -Description "EnableSetTimeLimitForActiveButIdleRemoteDesktopSessions15Mins"

        # 7. Check Remote Assistance
        Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
            -Name "fAllowToGetHelp" `
            -ExpectedValue 0 `
            -Description "RemoteAssistanceDisableConfigureOfferRemoteAssistance"

        # 8. Check Force Shutdown Restrictions
        Check-RegistrySetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
            -Name "ShutdownWithoutLogon" `
            -ExpectedValue 0 `
            -Description "RestrictForceShutdownToAdminGroupUsersWithNeed"

        # 9. Check Drive Redirection
        Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
            -Name "fDisableCdm" `
            -ExpectedValue 1 `
            -Description "VerifyDriveRedirectionIsNotConfiguredByDefault"
    }
    catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking Remote Access Security settings: $_"
    }
}

# Add these new check functions first:

function Check-UACAdvancedSettings {
    # Add checks for UAC advanced settings
    Check-RegistrySetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -ExpectedValue 2 -Description "ElevationPromptForAdminsInAdminApprovalModeConsentOnSecureDesktop"
    Check-RegistrySetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -ExpectedValue 1 -Description "ElevationPromptForStandardUsersCredentialsOnSecureDesktop"
    Check-RegistrySetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableInstallerDetection" -ExpectedValue 1 -Description "DetectAppInstallsPromptForElevationEnabled"
    Check-RegistrySetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableSecureUIAPaths" -ExpectedValue 1 -Description "ElevateUIAccessAppsInSecureLocationsEnabled"
    Check-RegistrySetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -ExpectedValue 1 -Description "SwitchToSecureDesktopWhenPromptingForElevationEnabled"
    Check-RegistrySetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableVirtualization" -ExpectedValue 1 -Description "VirtualizeFileRegistryWritesToPerUserLocationsEnabled"
}

function Check-SecurityAuditingSettings {
#    Check-RegistrySetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -ExpectedValue 1 -Description "AuditPolicies"
    Check-RegistrySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security" -Name "MaxSize" -ExpectedValue 4194240 -Description "EventLogSize"
}

function Check-DeviceAndMediaRestrictions {
    param (
        [string]$Description
    )
    
    $cdDvdPath = "HKLM:\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56308-b6bf-11d0-94f2-00a0c91efb8b}"
    
    try {
        # Check both read and write restrictions
        $readDeny = Check-RegistrySetting -Path $cdDvdPath `
            -Name "Deny_Read" `
            -ExpectedValue 1 `
            -Description "RemovableStorageEnableCdAndDvdDeny"
            
        $writeDeny = Check-RegistrySetting -Path $cdDvdPath `
            -Name "Deny_Write" `
            -ExpectedValue 1 `
            -Description "RemovableStorageEnableCdAndDvdDeny"
            
        # Only mark as applied if both restrictions are in place
        if ($readDeny -and $writeDeny) {
            Add-Result -Description $Description -Status "Applied" -Details "CD/DVD read and write access denied"
        } else {
            Add-Result -Description $Description -Status "Not Applied" -Details "CD/DVD restrictions incomplete"
        }
    }
    catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking CD/DVD restrictions: $_"
    }
}

function Check-NetworkAdapters {
    param (
        [string]$Description
    )
    
    try {
        $adapters = Get-NetAdapter -ErrorAction SilentlyContinue
        Add-Result -Description $Description -Status "Not Applied" -Details "Manual verification required"
    }
    catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking network adapters: $_"
    }
}

# Add these additional functions
function Check-LogonBanner {
    param (
        [string]$Description
    )
    
    try {
        # Check Legal Notice Caption
        Check-RegistrySetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
            -Name "LegalNoticeCaption" `
            -ExpectedValue "Warning!" `
            -Description "LoginBanner"

        # Check Legal Notice Text
        Check-RegistrySetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
            -Name "LegalNoticeText" `
            -ExpectedValue "*" `
            -Description "MessageTitleForLogonAttemptsDisplayWarningBanner"
    }
    catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking logon banner: $_"
    }
}

function Check-SecurityPolicies {
    # Password Policies
    $securityPolicy = SecEdit /Export /cfg "$env:TEMP\secpol.cfg"
    $passwordPolicy = Get-Content "$env:TEMP\secpol.cfg" | Select-String "PasswordComplexity"
    Add-Result -Description "PasswordPolicies" -Status $(if ($passwordPolicy -match "1") { "Applied" } else { "Not Applied" })
    
    # Lockout Policies
    $lockoutPolicy = Get-Content "$env:TEMP\secpol.cfg" | Select-String "LockoutDuration"
    Add-Result -Description "LockoutPolicies" -Status $(if ($lockoutPolicy -match "15") { "Applied" } else { "Not Applied" })
    
    Remove-Item "$env:TEMP\secpol.cfg" -Force
}

# Add these functions after the existing function definitions but before the "Run all checks" section:

function Check-UnnecessaryPrograms {
    param (
        [string]$Description
    )
    
    try {
        # Get list of installed programs
        $installedPrograms = Get-WmiObject -Class Win32_Product
        
        # Add your specific program checks here
        # This is a placeholder - customize based on your requirements
        Add-Result -Description $Description -Status "Not Applied" -Details "Manual verification required"
    }
    catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking programs: $_"
    }
}

function Check-ServiceDisabled {
    param (
        [string]$ServiceName,
        [string]$Description
    )
    
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        
        if ($null -eq $service) {
            Add-Result -Description $Description -Status "Not Found" -Details "Service not found"
        }
        else {
            $details = "Expected: Disabled, Found: $($service.Status)"
            if ($service.Status -eq 'Stopped' -and $service.StartType -eq 'Disabled') {
                Add-Result -Description $Description -Status "Applied" -Details $details
            }
            else {
                Add-Result -Description $Description -Status "Not Applied" -Details $details
            }
        }
    }
    catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking service: $_"
    }
}

function Check-UserAccounts {
    param (
        [string]$Description,
        [string]$AccountType
    )
    
    try {
        $accounts = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
        Add-Result -Description $Description -Status "Not Applied" -Details "Manual verification required"
    }
    catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking user accounts: $_"
    }
}

function Check-AdminRenamed {
    param (
        [string]$Description
    )
    
    try {
        $adminAccount = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
        if ($null -eq $adminAccount) {
            Add-Result -Description $Description -Status "Applied" -Details "Administrator account has been renamed"
        }
        else {
            Add-Result -Description $Description -Status "Not Applied" -Details "Administrator account still has default name"
        }
    }
    catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking admin account: $_"
    }
}

function Check-GuestDisabled {
    param (
        [string]$Description
    )
    
    try {
        $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        if ($null -eq $guestAccount -or $guestAccount.Enabled -eq $false) {
            Add-Result -Description $Description -Status "Applied" -Details "Guest account is disabled"
        }
        else {
            Add-Result -Description $Description -Status "Not Applied" -Details "Guest account is enabled"
        }
    }
    catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking guest account: $_"
    }
}

function Check-ServiceAccounts {
    param (
        [string]$Description
    )
    
    try {
        # This would need to be customized for your environment
        Add-Result -Description $Description -Status "Not Applied" -Details "Manual verification required"
    }
    catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking service accounts: $_"
    }
}

function Check-SecuritySoftware {
    param (
        [string]$Description
    )
    
    try {
        # Check for antivirus
        $avStatus = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct -ErrorAction SilentlyContinue
        if ($null -ne $avStatus) {
            Add-Result -Description $Description -Status "Applied" -Details "Antivirus software detected"
        }
        else {
            Add-Result -Description $Description -Status "Not Applied" -Details "No antivirus software detected"
        }
    }
    catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking security software: $_"
    }
}

function Check-AuditPolicies {
    param (
        [string]$Description
    )
    
    try {
        $auditpol = auditpol /get /category:* | Out-String
        Add-Result -Description $Description -Status "Not Applied" -Details "Manual verification required"
    }
    catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking audit policies: $_"
    }
}

function Check-NTPConfiguration {
    param (
        [string]$Description
    )
    
    try {
        $w32TimeService = Get-Service -Name "W32Time"
        if ($w32TimeService.Status -eq 'Running') {
            Add-Result -Description $Description -Status "Applied" -Details "NTP service is running"
        }
        else {
            Add-Result -Description $Description -Status "Not Applied" -Details "NTP service is not running"
        }
    }
    catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking NTP configuration: $_"
    }
}

function Check-USBStorageRestrictions {
    param (
        [string]$Description
    )
    
    try {
        # Check USB storage restrictions in registry
        Check-RegistrySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" `
            -Name "Start" `
            -ExpectedValue 4 `
            -Description "DisableAllUsbPortsForStandardUsersUnlessNeeded"
    }
    catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking USB restrictions: $_"
    }
}

function Check-CDROMRestrictions {
    param (
        [string]$Description
    )
    
    try {
        # Check CD-ROM driver service state
        Check-RegistrySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Services\cdrom" `
            -Name "Start" `
            -ExpectedValue 4 `
            -Description "DisableCdRomDrivesForStandardUsers"

        # Additionally check for disabled CD-ROM devices
        $cdromDevices = Get-PnpDevice | Where-Object { $_.Class -eq "CDROM" }
        $allDisabled = $true
        $details = ""

        foreach ($device in $cdromDevices) {
            if ($device.Status -ne 'Disabled') {
                $allDisabled = $false
                $details += "Device '$($device.FriendlyName)' is not disabled; "
            }
        }

        if ($cdromDevices.Count -eq 0) {
            Add-Result -Description $Description -Status "Not Found" -Details "No CD-ROM devices found"
        }
        elseif ($allDisabled) {
            Add-Result -Description $Description -Status "Applied" -Details "All CD-ROM devices are disabled"
        }
        else {
            Add-Result -Description $Description -Status "Not Applied" -Details $details
        }
    }
    catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking CD-ROM restrictions: $_"
    }
}

function Check-AutorunSettings {
    param (
        [string]$Description
    )
    try {
        # Check autorun settings in registry
        Check-RegistrySetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
            -Name "NoDriveTypeAutoRun" `
            -ExpectedValue 255 `
            -Description "DisableAutorunForExternalMedia"
    }
    catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking autorun settings: $_"
    }
}

function Check-Firewall {
    param (
        [string]$Description
    )
    
    try {
        $firewall = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        if ($null -ne $firewall -and ($firewall | Where-Object { $_.Enabled -eq $true }).Count -eq 3) {
            Add-Result -Description $Description -Status "Applied" -Details "Firewall is enabled for all profiles"
        }
        else {
            Add-Result -Description $Description -Status "Not Applied" -Details "Firewall is not properly configured"
        }
    }
    catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking firewall: $_"
    }
}

# Add these new functions

function Check-PasswordPolicies {
    param (
        [string]$Description
    )
    try {
        $securityPolicy = SecEdit /Export /cfg "$env:TEMP\secpol.cfg"
        $passwordPolicy = Get-Content "$env:TEMP\secpol.cfg" | Select-String "PasswordComplexity"
        if ($passwordPolicy -match "1") {
            Add-Result -Description $Description -Status "Applied" -Details "Password complexity enabled"
        } else {
            Add-Result -Description $Description -Status "Not Applied" -Details "Password complexity not enabled"
        }
        Remove-Item "$env:TEMP\secpol.cfg" -Force
    }
    catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking password policies: $_"
    }
}

function Check-UACSettings {
    param (
        [string]$Description,
        [string]$RegistryName,
        [int]$ExpectedValue
    )
    Check-RegistrySetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name $RegistryName -ExpectedValue $ExpectedValue -Description $Description
}

function Check-InteractiveLogonPolicy {
    param (
        [string]$PolicyName,
        [string]$ExpectedValue,
        [string]$Description
    )
    try {
        $path = "HKLM:\\" + ($PolicyName -replace "MACHINE\\", "")
        Check-RegistrySetting -Path $path -Name ($PolicyName.Split('\')[-1]) -ExpectedValue $ExpectedValue -Description $Description
    }
    catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking interactive logon policy: $_"
    }
}

function Check-NTLMSettings {
    param (
        [string]$Description
    )
    Check-RegistrySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ExpectedValue 5 -Description $Description
}

function Check-AnonymousEnumeration {
    param (
        [string]$Description
    )
    Check-RegistrySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -ExpectedValue 1 -Description $Description
}

function Check-RecoveryConsoleSettings {
    param (
        [string]$Description
    )
    Check-RegistrySetting -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole" -Name "SecurityLevel" -ExpectedValue 0 -Description $Description
}

function Check-UserRightAssignment {
    param (
        [string]$RightName,
        [string]$Description,
        [bool]$ShouldBeEmpty,
        [string[]]$AllowedAccounts
    )
    try {
        $secedit = SecEdit /Export /cfg "$env:TEMP\secpol.cfg"
        $rights = Get-Content "$env:TEMP\secpol.cfg" | Select-String $RightName
        
        if ($ShouldBeEmpty -and $rights -match "\*S-1-") {
            Add-Result -Description $Description -Status "Not Applied" -Details "Right should be empty but has assignments"
        }
        elseif (-not $ShouldBeEmpty) {
            $currentAccounts = ($rights -split "=")[1].Trim()
            $matchesExpected = $true
            foreach ($account in $AllowedAccounts) {
                if ($currentAccounts -notmatch [regex]::Escape($account)) {
                    $matchesExpected = $false
                    break
                }
            }
            Add-Result -Description $Description -Status $(if ($matchesExpected) { "Applied" } else { "Not Applied" }) -Details "Current assignments: $currentAccounts"
        }
        else {
            Add-Result -Description $Description -Status "Applied" -Details "No assignments found"
        }
        Remove-Item "$env:TEMP\secpol.cfg" -Force
    }
    catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking user rights: $_"
    }
}

# Modify this function in the existing script to improve the registry check
function Check-DeviceInstallationSettings {
    param (
        [string]$Description
    )
    
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
        
        # Add debug output
        Write-Host "Checking Device Installation Settings at: $regPath"
        Write-Host "Path exists: $(Test-Path $regPath)"
        
        if (Test-Path $regPath) {
            $actualValue = (Get-ItemProperty -Path $regPath -Name "AllowAdminInstall" -ErrorAction SilentlyContinue).AllowAdminInstall
            Write-Host "Found value: $actualValue"
            
            if ($null -eq $actualValue) {
                Add-Result -Description "DeviceInstallAllowAdminsToOverrideInstallRestrictions" `
                    -Status "Not Found" `
                    -Details "Registry value 'AllowAdminInstall' not found"
            }
            else {
                $details = "Expected: 1, Found: $actualValue"
                if ($actualValue -eq 1) {
                    Add-Result -Description "DeviceInstallAllowAdminsToOverrideInstallRestrictions" `
                        -Status "Applied" `
                        -Details $details
                }
                else {
                    Add-Result -Description "DeviceInstallAllowAdminsToOverrideInstallRestrictions" `
                        -Status "Not Applied" `
                        -Details $details
                }
            }
        }
        else {
            Add-Result -Description "DeviceInstallAllowAdminsToOverrideInstallRestrictions" `
                -Status "Not Found" `
                -Details "Registry path not found"
        }
    }
    catch {
        Add-Result -Description "DeviceInstallAllowAdminsToOverrideInstallRestrictions" `
            -Status "Error" `
            -Details "Error checking device installation settings: $_"
    }
}

function Check-RemovableStorageAccess {
    param (
        [string]$Description
    )
    
    try {
        # Check removable storage access restrictions
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices"
        
        if (Test-Path $regPath) {
            $denyAll = (Get-ItemProperty -Path $regPath -Name "Deny_All" -ErrorAction SilentlyContinue).Deny_All
            
            if ($null -eq $denyAll) {
                Add-Result -Description $Description -Status "Not Found" -Details "Deny_All setting not found"
            }
            else {
                $details = "Expected: 1, Found: $denyAll"
                if ($denyAll -eq 1) {
                    Add-Result -Description $Description -Status "Applied" -Details $details
                }
                else {
                    Add-Result -Description $Description -Status "Not Applied" -Details $details
                }
            }
        }
        else {
            Add-Result -Description $Description -Status "Not Found" -Details "Registry path not found"
        }
    }
    catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking removable storage access: $_"
    }
}

function Check-NetworkSettings {
    param (
        [string]$Description
    )
    Check-RegistrySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -ExpectedValue 2 -Description $Description
}

function Check-PowerShellSettings {
    param (
        [string]$Description
    )
    Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Name "EnableScriptBlockLogging" -ExpectedValue 1 -Description $Description
}

function Check-AuditPolicies {
    param (
        [string]$Description
    )
    
    try {
        # Export current audit policy to a temporary file
        $auditPolicyOutput = auditpol /get /category:* | Out-String
        
        # Check if key audit policies are enabled
        $requiredPolicies = @(
            "Credential Validation",
            "Application Group Management",
            "Computer Account Management",
            "Distribution Group Management",
            "Other Account Management Events",
            "Security Group Management",
            "User Account Management"
            
        )

        $policyStatus = $true
        $details = ""

        foreach ($policy in $requiredPolicies) {
            if ($auditPolicyOutput -match [regex]::Escape($policy)) {
                $line = ($auditPolicyOutput -split "`n" | Where-Object { $_ -match [regex]::Escape($policy) }).Trim()
                if ($line -notmatch "Success and Failure") {
                    $policyStatus = $false
                    $details += "$policy not fully enabled; "
                }
            }
        }

        if ($policyStatus) {
            Add-Result -Description $Description -Status "Applied" -Details "Audit policies are correctly configured"
        } else {
            Add-Result -Description $Description -Status "Not Applied" -Details $details
        }
    }
    catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking audit policies: $_"
    }
}

function Check-RemovableDiskExecuteRestrictions {
    param (
        [string]$Description
    )
    
    try {
        $srpPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Paths"
        
        if (Test-Path $srpPath) {
            $hasRestrictions = $false
            $details = ""
            
            # Check all numbered paths
            Get-ChildItem $srpPath | ForEach-Object {
                $itemData = Get-ItemProperty -Path $_.PSPath -Name "ItemData" -ErrorAction SilentlyContinue
                $saferFlags = Get-ItemProperty -Path $_.PSPath -Name "SaferFlags" -ErrorAction SilentlyContinue
                
                if ($itemData.ItemData -like "*:\*" -and $saferFlags.SaferFlags -eq 0) {
                    $hasRestrictions = $true
                    $details += "Found restriction for $($itemData.ItemData); "
                }
            }
            
            if ($hasRestrictions) {
                Add-Result -Description $Description -Status "Applied" -Details $details
            } else {
                Add-Result -Description $Description -Status "Not Applied" -Details "No removable disk execute restrictions found"
            }
        } else {
            Add-Result -Description $Description -Status "Not Found" -Details "Software Restriction Policies path not found"
        }
    }
    catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking removable disk execute restrictions: $_"
    }
}

function Check-SmartScreenSettings {
    param (
        [string]$Description
    )
    
    try {
        $regPath = "HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter"
        
        # Check both required settings
        $enabled = Check-RegistrySetting -Path $regPath `
            -Name "EnabledV9" `
            -ExpectedValue 1 `
            -Description "ActivateSmartScreenViaMicrosoftDefenderEtcManagedByGroupPolicy"
            
        $preventOverride = Check-RegistrySetting -Path $regPath `
            -Name "PreventOverride" `
            -ExpectedValue 1 `
            -Description "ActivateSmartScreenViaMicrosoftDefenderEtcManagedByGroupPolicy"
        
        # Only mark as applied if both settings are correct
        if ($enabled -and $preventOverride) {
            Add-Result -Description $Description -Status "Applied" -Details "SmartScreen is enabled and prevent override is set"
        } else {
            Add-Result -Description $Description -Status "Not Applied" -Details "SmartScreen settings are incomplete"
        }
    }
    catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking SmartScreen settings: $_"
    }
}

# Add this function to check Edge Hardening policies
function Check-EdgeHardeningSettings {
    param (
        [string]$Description
    )
    
    try {
        # 1. Windows Ink Workspace Settings
        Check-RegistrySetting -Path "HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace" `
            -Name "AllowWindowsInkWorkspace" `
            -ExpectedValue 0 `
            -Description "DisableAllowWindowsInkWorkspace"

        Check-RegistrySetting -Path "HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace" `
            -Name "AllowSuggestedAppsInWindowsInkWorkspace" `
            -ExpectedValue 0 `
            -Description "DisableAllowSuggestedAppsInWindowsInkWorkspace"

        # 2. Windows Error Reporting
        Check-RegistrySetting -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting" `
            -Name "Disabled" `
            -ExpectedValue 1 `
            -Description "EnableTurnOffWindowsErrorReporting"

        # 3. Windows Customer Experience Improvement Program
        Check-RegistrySetting -Path "HKLM:\Software\Policies\Microsoft\SQMClient\Windows" `
            -Name "CEIPEnable" `
            -ExpectedValue 0 `
            -Description "EnableTurnOffWindowsCustomerExpImprovementProgram"

        # 4. Windows Messenger CEIP
        Check-RegistrySetting -Path "HKLM:\Software\Policies\Microsoft\Messenger\Client" `
            -Name "CEIP" `
            -ExpectedValue 2 `
            -Description "EnableTurnOffTheWindowsMessengerCustomerExpImprovementProgram"

        # 5. Publish to Web Task
        Check-RegistrySetting -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
            -Name "NoPublishingWizard" `
            -ExpectedValue 1 `
            -Description "EnableTurnOffThePublishToWebTaskForFilesAndFolders"

        # 6. Order Prints Picture Task
        Check-RegistrySetting -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
            -Name "NoOnlinePrintsWizard" `
            -ExpectedValue 1 `
            -Description "EnableTurnOffTheOrderPrintsPictureTask"

        # 7. Search Companion Updates
        Check-RegistrySetting -Path "HKLM:\Software\Policies\Microsoft\SearchCompanion" `
            -Name "DisableContentFileUpdates" `
            -ExpectedValue 1 `
            -Description "EnableTurnOffSearchCompanionContentFileUpdates"

        # 8. Microsoft Maps
        Check-RegistrySetting -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" `
            -Name "SpynetReporting" `
            -ExpectedValue 0 `
            -Description "DisableJoinMicrosoftMaps"

        Check-RegistrySetting -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" `
            -Name "SubmitSamplesConsent" `
            -ExpectedValue 2 `
            -Description "DisableJoinMicrosoftMaps"

        # 9. Internet Explorer
        # Check if Internet Explorer feature is disabled
        $ieFeature = Get-WindowsOptionalFeature -Online -FeatureName "Internet-Explorer-Optional-amd64" -ErrorAction SilentlyContinue
        if ($ieFeature.State -eq "Disabled") {
            Add-Result -Description "DisableInternetExplorerOnUnnecessaryWorkstationsEtc" `
                -Status "Applied" `
                -Details "Internet Explorer feature is disabled"
        } else {
            Add-Result -Description "DisableInternetExplorerOnUnnecessaryWorkstationsEtc" `
                -Status "Not Applied" `
                -Details "Internet Explorer feature is not disabled"
        }
    }
    catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking Edge Hardening settings: $_"
    }
}

# Add this function with the others (keep all existing functions)
function Check-OtherFolderSettings {
    param (
        [string]$Description
    )
    
    try {
        # 1. Check Windows App Data Sharing
        Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager" `
            -Name "AllowSharedLocalAppData" `
            -ExpectedValue 0 `
            -Description "DisableAllowAWindowsAppToShareApplicationData"

        # 2. Check PIN Sign-in
        Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
            -Name "AllowDomainPINLogon" `
            -ExpectedValue 0 `
            -Description "DisableTurnOnConveniencePinSignIn"

        # 3. Check Device Authentication
        Check-RegistrySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" `
            -Name "DeviceAuthEnabled" `
            -ExpectedValue 1 `
            -Description "EnableSupportDeviceAuthenticationUsingCertificateAutomatic"

        # 4. Check App Notifications
        Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
            -Name "DisableLockScreenAppNotifications" `
            -ExpectedValue 1 `
            -Description "EnableTurnOffAppNotificationsOnTheLockScreen"

        # 5. Check Picture Password
        Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
            -Name "BlockDomainPicturePassword" `
            -ExpectedValue 1 `
            -Description "EnableTurnOffPicturePasswordSignIn"

        # 6. Check Windows NTP Client
        Check-RegistrySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" `
            -Name "Type" `
            -ExpectedValue "NTP" `
            -Description "EnableWindowsNtpClient"
    }
    catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking other folder settings: $_"
    }
}

# Add this function with your other check functions:
function Check-SystemHardeningPolicies {
    param (
        [string]$Description
    )
    
    try {
        # 1. Check Internet Resource Contact
        Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard" `
            -Name "ExitOnMSICW" `
            -ExpectedValue 1 `
            -Description "ComputersWillBeConfiguredToNotContactInternetResources"

        # 2. Check NTP Configuration
        Check-RegistrySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" `
            -Name "Type" `
            -ExpectedValue "NTP" `
            -Description "ConfigureNtp"

        # 3. Check System Shutdown Settings
        Check-RegistrySetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
            -Name "ShutdownWithoutLogon" `
            -ExpectedValue 0 `
            -Description "DisableAllowSystemToBeShutDownWithoutHavingToLogOn"

        # 4. Check Temp Folder Deletion
        Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
            -Name "DeleteTempDirsOnExit" `
            -ExpectedValue 1 `
            -Description "DisableDoNotDeleteTempFoldersUponExit"

        # 5. Check Font Providers
        Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
            -Name "EnableFontProviders" `
            -ExpectedValue 0 `
            -Description "DisableEnableFontProviders"

        # 6. Check Guest Logons
        Check-RegistrySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
            -Name "AllowInsecureGuestAuth" `
            -ExpectedValue 0 `
            -Description "DisableEnableInsecureGuestLogons"

        # 7. Check Machine Account Password Changes
        Check-RegistrySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
            -Name "RefusePasswordChange" `
            -ExpectedValue 0 `
            -Description "DisableRefuseMachineAccountPasswordChanges"

        # 8. Check Group Policy Background Refresh
        Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" `
            -Name "NoBackgroundPolicy" `
            -ExpectedValue 0 `
            -Description "DisableTurnOffBackgroundRefreshOfGroupPolicy"

        # 9. Check Temporary Folders Per Session
        Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
            -Name "PerSessionTempDir" `
            -ExpectedValue 1 `
            -Description "EnableDoNotUseTemporaryFoldersPerSession"

        # 10. Check Security Software
        $avStatus = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct -ErrorAction SilentlyContinue
        if ($null -ne $avStatus) {
            Add-Result -Description "DeploySecuritySoftwareAntiVirusWhitelistingPerOpsMaintFramework" `
                -Status "Applied" `
                -Details "Security software detected"
        } else {
            Add-Result -Description "DeploySecuritySoftwareAntiVirusWhitelistingPerOpsMaintFramework" `
                -Status "Not Applied" `
                -Details "No security software detected"
        }
    }
    catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking System Hardening settings: $_"
    }
}

# Add this function with your other check functions:
function Check-UserAccountSecurityPolicies {
    param (
        [string]$Description
    )
    
    try {
        # 1. Admin Approval Mode
        Check-RegistrySetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
            -Name "FilterAdministratorToken" `
            -ExpectedValue 1 `
            -Description "AdminApprovalModeForBuiltInAdminAccountEnabled"

        # 2. Password Policies
        $secpolPath = "$env:TEMP\secpol.cfg"
        secedit /export /cfg $secpolPath | Out-Null
        $passwordPolicies = Get-Content $secpolPath | Select-String "PasswordComplexity", "MinimumPasswordLength"
        
        if (($passwordPolicies | Select-String "PasswordComplexity = 1") -and 
            ($passwordPolicies | Select-String "MinimumPasswordLength = [8-9]|1[0-4]")) {
            Add-Result -Description "ConfigurePasswordPoliciesPerAccessControlFramework" `
                -Status "Applied" `
                -Details "Password policies meet requirements"
        } else {
            Add-Result -Description "ConfigurePasswordPoliciesPerAccessControlFramework" `
                -Status "Not Applied" `
                -Details "Password policies do not meet requirements"
        }
        Remove-Item $secpolPath -Force

        # 3. Standard User Elevation Prompt
        Check-RegistrySetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
            -Name "ConsentPromptBehaviorUser" `
            -ExpectedValue 0 `
            -Description "DenyBehaviorOfTheElevationPromptForStandardUsers"

        # 4. Application Installation Detection
        Check-RegistrySetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
            -Name "EnableInstallerDetection" `
            -ExpectedValue 1 `
            -Description "DetectAppInstallsPromptForElevationEnabled"

        # 5. Administrator Account Enumeration
        Check-RegistrySetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" `
            -Name "EnumerateAdministrators" `
            -ExpectedValue 0 `
            -Description "DisableEnumerateAdministratorAccountsOnElevation"

        # 6. Guest Account Status
        $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        if ($null -eq $guestAccount -or $guestAccount.Enabled -eq $false) {
            Add-Result -Description "DisableBuiltInGuestAccount" `
                -Status "Applied" `
                -Details "Guest account is disabled"
        } else {
            Add-Result -Description "DisableBuiltInGuestAccount" `
                -Status "Not Applied" `
                -Details "Guest account is enabled"
        }

        # 7. Service Account Interactive Login
        $services = Get-WmiObject -Class Win32_Service | Where-Object { $_.StartName -notlike "NT *" -and $_.StartName -ne "LocalSystem" }
        $interactiveServiceFound = $false
        foreach ($service in $services) {
            if ($service.StartName -match "^(?!NT|Local).*$") {
                $interactiveServiceFound = $true
                break
            }
        }
        Add-Result -Description "DisableInteractiveLoginsForNonHumanServiceAccounts" `
            -Status $(if (-not $interactiveServiceFound) { "Applied" } else { "Not Applied" }) `
            -Details "Service account interactive login status"

        # 8. Standard User Accounts Configuration
        Add-Result -Description "ConfigureStandardUserAccountsPerAccessControlFramework" `
            -Status "Manual Check Required" `
            -Details "Standard user accounts configuration needs manual verification"

        # 9. Admin Accounts Configuration
        Add-Result -Description "ConfigureAdminAccountsPerAccessControlFramework" `
            -Status "Manual Check Required" `
            -Details "Admin accounts configuration needs manual verification"
    }
    catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking User Account Security settings: $_"
    }
}

# Add this function to handle Windows Ink Workspace settings checks
function Check-WindowsInkWorkspaceSettings {
    param (
        [string]$Description
    )
    
    try {
        # Check Windows Ink Workspace settings
        Check-RegistrySetting -Path "HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace" `
            -Name "AllowWindowsInkWorkspace" `
            -ExpectedValue 0 `
            -Description "DisableAllowWindowsInkWorkspace"

        # Check Suggested Apps in Windows Ink Workspace
        Check-RegistrySetting -Path "HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace" `
            -Name "AllowSuggestedAppsInWindowsInkWorkspace" `
            -ExpectedValue 0 `
            -Description "DisableAllowSuggestedAppsInWindowsInkWorkspace"
    }
    catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking Windows Ink Workspace settings: $_"
    }
}

# Update the registry check for internet access restrictions
function Check-InternetAccessRestrictions {
    param (
        [string]$Description
    )
    
    try {
        # Define the registry path
        $regPath = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
        
        # First check if the path exists
        if (-not (Test-Path $regPath)) {
            Add-Result -Description $Description `
                -Status "Not Found" `
                -Details "Registry path not found: $regPath"
            return
        }

        # Check each required setting
        $proxyEnabled = $false
        $proxyServer = $false
        $proxyOverride = $false
        $details = ""

        try {
            $settings = Get-ItemProperty -Path $regPath -ErrorAction Stop
            $proxyEnabled = ($settings.ProxyEnable -eq 1)
            $proxyServer = ($settings.ProxyServer -eq "127.0.0.1:8080")
            $proxyOverride = ($settings.ProxyOverride -eq "<local>")
            
            $details += "Proxy Enabled: $proxyEnabled; "
            $details += "Proxy Server: $($settings.ProxyServer); "
            $details += "Proxy Override: $($settings.ProxyOverride); "
        }
        catch {
            $details += "Error reading proxy settings; "
        }

        # Check firewall rule
        $firewallRule = Get-NetFirewallRule -DisplayName "Block Internet Access" -ErrorAction SilentlyContinue
        $firewallEnabled = $false
        
        if ($firewallRule) {
            $firewallEnabled = ($firewallRule.Enabled -eq $true -and 
                              $firewallRule.Direction -eq "Outbound" -and 
                              $firewallRule.Action -eq "Block")
            $details += "Firewall rule found and properly configured: $firewallEnabled"
        }
        else {
            $details += "Firewall rule 'Block Internet Access' not found"
        }
        
        # Determine overall status
        if ($proxyEnabled -and $proxyServer -and $proxyOverride -and $firewallEnabled) {
            Add-Result -Description $Description `
                -Status "Applied" `
                -Details $details
        }
        else {
            Add-Result -Description $Description `
                -Status "Not Applied" `
                -Details $details
        }
    }
    catch {
        Add-Result -Description $Description `
            -Status "Error" `
            -Details "Error checking internet access restrictions: $_"
    }
}

# Run all checks
Write-Host "Running security configuration checks..."

# 1. Programs and Services
Check-UnnecessaryPrograms -Description "Remove all unnecessary programs and applications"
Check-ServiceDisabled -ServiceName "TlntSvr" -Description "Disable Telnet service"
Check-ServiceDisabled -ServiceName "Tftpd" -Description "Disable TFTP service"
Check-ServiceDisabled -ServiceName "RemoteRegistry" -Description "Disable Remote Registry service"

# 2. User Account Controls
Check-UserAccounts -Description "Configure standard user accounts" -AccountType "Standard"
Check-UserAccounts -Description "Configure administrator accounts" -AccountType "Admin"
Check-AdminRenamed -Description "Rename built-in administrator account"
Check-GuestDisabled -Description "Disable built-in guest account"
Check-ServiceAccounts -Description "Configure non-human service accounts to disallow interactive logins"

# 3. Security Software and Settings
Check-SecuritySoftware -Description "Deploy and configure security software"
Check-AuditPolicies -Description "AuditPolicies"  # Keep this one
Check-PasswordPolicies -Description "Configure password policies"

# 4. Device and Media Controls
Check-USBStorageRestrictions -Description "Disable USB ports for standard users"
Check-CDROMRestrictions -Description "Disable CD-ROM drives for standard users"
Check-AutorunSettings -Description "Disable 'Autorun' capability for all external media"
Check-RemovableDiskExecuteRestrictions -Description "RemovableStorageEnableRemovableDiskDenyExecute"

# 5. Network Security
Write-Host "Checking Network Security Settings..." -ForegroundColor Cyan
Check-NetworkSecuritySettings -Description "NetworkSecuritySettings"

# 6. UAC Settings
Check-UACSettings -Description "Set UAC to highest level" -RegistryName "ConsentPromptBehaviorAdmin" -ExpectedValue 2

# Device Installation Message Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DisplayCustomMessage" -ExpectedValue 1 -Description "DeviceInstallDisplayCustomMessageWhenInstallIsPrevented"
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DisplayCustomTitle" -ExpectedValue 1 -Description "DeviceInstallDisplayCustomTitleWhenInstallIsPrevented"

# Removable Storage Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices" -Name "Deny_CD_DVD" -ExpectedValue 1 -Description "RemovableStorageEnableCdAndDvdDeny"
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices" -Name "Deny_Execute" -ExpectedValue 1 -Description "RemovableStorageEnableRemovableDiskDenyExecute"

# Interactive Logon Policies
Check-InteractiveLogonPolicy -PolicyName "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName" -ExpectedValue "1" -Description "Security Option: Interactive Logon - Do not display last user name"
Check-InteractiveLogonPolicy -PolicyName "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD" -ExpectedValue "0" -Description "Set the 'Do not require CTRL+ALT+DEL' policy setting to Disabled"
Check-InteractiveLogonPolicy -PolicyName "MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse" -ExpectedValue "1" -Description "Set the 'Limit local account use of blank passwords to console logon only' right to Enable"

# Check Logon Banner
Check-LogonBanner -Description "Configure the logon message title and text for users attempting to log on"

# NTLM and LAN Manager Settings
Check-NTLMSettings -Description "Disable LAN Manager hash use and enable NTLMv2"

# Anonymous Enumeration Settings
Check-AnonymousEnumeration -Description "Set the 'Do not allow anonymous enumeration of SAM accounts and shares' policy setting to Enabled"

# Recovery Console Settings
Check-RecoveryConsoleSettings -Description "Set the 'Recovery Console: Allow automatic administrative logon' policy setting to Disabled"

# User Rights Assignments
Check-UserRightAssignment -RightName "SeTcbPrivilege" -Description "Remove the 'Act as part of the operating system' right from all accounts" -ShouldBeEmpty $true
Check-UserRightAssignment -RightName "SeDebugPrivilege" -Description "Remove the 'Debug programs' right from all accounts unless necessary" -AllowedAccounts @("*S-1-5-32-544") # Only Administrators
Check-UserRightAssignment -RightName "SeNetworkLogonRight" -Description "Restrict 'Access this computer from the network' right" -AllowedAccounts @("*S-1-5-32-544", "*S-1-5-32-545") # Admins and Users
Check-UserRightAssignment -RightName "SeRemoteShutdownPrivilege" -Description "Restrict the 'Force Shutdown from a Remote System' policy to administrators" -AllowedAccounts @("*S-1-5-32-544") # Only Administrators

# Network Security Settings
Check-DeviceInstallationSettings -Description "Check device installation settings"

# Removable Storage Access
Check-RemovableStorageAccess -Description "Check removable storage access"

# Network Settings
Check-NetworkSettings -Description "Check network settings"

# PowerShell Settings
Check-PowerShellSettings -Description "Check PowerShell settings"

# Add these checks after your existing checks but before the compliance calculation

# Check Internet Resource Contact Settings
Check-InternetAccessRestrictions -Description "ComputersWillBeConfiguredToNotContactInternetResources"

# Check Machine Account Password Settings
Check-RegistrySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RefusePasswordChange" -ExpectedValue 1 -Description "DisableRefuseMachineAccountPasswordChanges"

# Check Secure Channel Settings
Check-RegistrySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "SignSecureChannel" -ExpectedValue 1 -Description "EnableDigitallyEncryptOrSignSecureChannelDataAlways"

# Check Session Key Settings
Check-RegistrySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireStrongKey" -ExpectedValue 1 -Description "EnableRequireStrongSessionKey"

# Check System Shutdown Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -ExpectedValue 0 -Description "DisableAllowSystemToBeShutDownWithoutHavingToLogOn"

# Check Guest Logon Settings
Check-RegistrySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "AllowInsecureGuestAuth" -ExpectedValue 0 -Description "DisableEnableInsecureGuestLogons"

# Check Mapper I/O Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" -Name "AllowLLTDIO" -ExpectedValue 0 -Description "DisableTurnOnMapperIoLltddioDriver"

# Check Responder Driver Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" -Name "AllowRspndr" -ExpectedValue 0 -Description "DisableTurnOnResponderRspndrDriver"

# Check Group Policy Refresh Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name "NoBackgroundPolicy" -ExpectedValue 0 -Description "DisableTurnOffBackgroundRefreshOfGroupPolicy"

# Check Print Driver Download Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableWebPnPDownload" -ExpectedValue 1 -Description "EnableTurnOffDownloadingOfPrintDriversOverHttp"

# Check Internet Download Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoWebServices" -ExpectedValue 1 -Description "EnableTurnOffInternetDownloadForWebPublishingOnlineOrdering"

# Check HTTP Printing Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableHTTPPrinting" -ExpectedValue 1 -Description "EnableTurnOffPrintingOverHttp"

# Check Picture Ordering Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoOnlinePrintsWizard" -ExpectedValue 1 -Description "EnableTurnOffTheOrderPrintsPictureTask"

# Check Web Publishing Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoPublishingWizard" -ExpectedValue 1 -Description "EnableTurnOffThePublishToWebTaskForFilesAndFolders"

# Check Windows Messenger Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" -Name "CEIP" -ExpectedValue 0 -Description "EnableTurnOffTheWindowsMessengerCustomerExpImprovementProgram"

# Check Windows Customer Experience Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -ExpectedValue 0 -Description "EnableTurnOffWindowsCustomerExpImprovementProgram"

# Check Windows Error Reporting Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -ExpectedValue 1 -Description "EnableTurnOffWindowsErrorReporting"

# Check Device Authentication Settings
Check-RegistrySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "UseMachineId" -ExpectedValue 1 -Description "EnableSupportDeviceAuthenticationUsingCertificate"

# Check App Notifications Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableLockScreenAppNotifications" -ExpectedValue 1 -Description "EnableTurnOffAppNotificationsOnTheLockScreen"

# Check Picture Password Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "BlockDomainPicturePassword" -ExpectedValue 1 -Description "EnableTurnOffPicturePasswordSignIn"

# Check PIN Sign-in Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowDomainPINLogon" -ExpectedValue 0 -Description "DisableTurnOnConveniencePinSignIn"

# Check App Data Sharing Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager" -Name "AllowSharedLocalAppData" -ExpectedValue 0 -Description "DisableAllowAWindowsAppToShareApplicationData"

# Check Microsoft Account Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MSAOptional" -ExpectedValue 1 -Description "EnableAllowMicrosoftAccountsToBeOptional"

# Check Password Reveal Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" -Name "DisablePasswordReveal" -ExpectedValue 1 -Description "EnableDoNotDisplayThePasswordRevealButton"

# Check RDP Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fPromptForPassword" -ExpectedValue 1 -Description "EnableDoNotAllowPasswordsToBeSavedInGpoForRemoteDesktop"

# Check Windows Store Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "RemoveWindowsStore" -ExpectedValue 1 -Description "DisableWindowsStoreOnUnnecessaryWorkstationsEtc"

# Check Windows Ink Settings
Check-WindowsInkWorkspaceSettings -Description "DisableAllowSuggestedAppsInWindowsInkWorkspace"

# Check Drive Redirection Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutoplayfornonVolume" -ExpectedValue 1 -Description "VerifyDriveRedirectionIsNotConfiguredByDefault"

# Check RDP Session Time Limit Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxIdleTime" -ExpectedValue 900000 -Description "EnableSetTimeLimitForActiveButIdleRemoteDesktopSessions15Mins"

# Check Recycle Bin Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\BitBucket" -Name "RetentionPeriod" -ExpectedValue 7 -Description "RecycleBinSettingFilesDeletedAfter7DaysRestrictRecycleBinStorage"

# SmartScreen Settings
Check-SmartScreenSettings -Description "ActivateSmartScreenViaMicrosoftDefenderEtcManagedByGroupPolicy"

# Device Installation Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "AllowAdminInstall" -ExpectedValue 1 -Description "DeviceInstallAllowAdminsToOverrideInstallRestrictions"

# FTP Settings
Check-RegistrySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Services\FTPSVC\Parameters" -Name "AllowAnonymous" -ExpectedValue 0 -Description "DisableAnonymousFtpFileShareOnWindowsMachine"

# Font Provider Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableFontProviders" -ExpectedValue 0 -Description "DisableEnableFontProviders"

# Administrator Enumeration Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" -Name "EnumerateAdministrators" -ExpectedValue 0 -Description "DisableEnumerateAdministratorAccountsOnElevation"

# Internet Explorer Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -ExpectedValue 1 -Description "DisableInternetExplorerOnUnnecessaryWorkstationsEtc"

# Microsoft Maps Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" -Name "AutoDownloadAndUpdateMapData" -ExpectedValue 0 -Description "DisableJoinMicrosoftMaps"

# DNS Client Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ExpectedValue 0 -Description "DnsClientEnableTurnOffMulticastNameResolution"

# Anonymous Enumeration Settings
Check-RegistrySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -ExpectedValue 1 -Description "DontAllowAnonymousEnumerationOfSamAcctsSharesEnabled"

# LAN Manager Hash Settings
Check-RegistrySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -ExpectedValue 1 -Description "DontStoreLanManagerHashOnNextPasswordChangeDisabled"

# Device Installation Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceClasses" -ExpectedValue 1 -Description "EnableDevicesPreventUsersFromInstallingPrinterDrivers"

# Printer Driver Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "RestrictDriverInstallationToAdministrators" -ExpectedValue 1 -Description "EnableLimitPrintDriverInstallationToAdministrators"

# Codec Download Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventCodecDownload" -ExpectedValue 1 -Description "EnablePreventCodecDownload"

# Device Authentication Settings
Check-RegistrySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "UseMachineId" -ExpectedValue 1 -Description "EnableSupportDeviceAuthenticationUsingCertificateAutomatic"

# Internet Connection Wizard Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard" -Name "ExitOnMSICW" -ExpectedValue 1 -Description "EnableTurnOffInternetConnectionWizardIfUrlReferringMicrosoftCom"

# Registration Wizard Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control" -Name "NoRegistration" -ExpectedValue 1 -Description "EnableTurnOffRegistrationIfUrlReferringToMicrosoftCom"

# Search Companion Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion" -Name "DisableContentFileUpdates" -ExpectedValue 1 -Description "EnableTurnOffSearchCompanionContentFileUpdates"

# Windows Time Service Settings
Check-RegistrySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -Name "Type" -ExpectedValue "NTP" -Description "EnableWindowsNtpClient"

# PowerShell Settings
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -ExpectedValue 1 -Description "WindowsPowerShellTurnOnModuleLogging"
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ExpectedValue 1 -Description "WindowsPowerShellTurnOnPowerShellScriptBlockLogging"
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -ExpectedValue 1 -Description "WindowsPowerShellTurnOnPowerShellTranscription"

# Running additional security configuration checks...

# UAC Advanced Settings
Check-UACAdvancedSettings

# Comment out this line
# Check-SecurityAuditingSettings

# Device and Media Restrictions
Check-DeviceAndMediaRestrictions

# Call the new functions
# Check-LoginBanner
Check-SecurityPolicies

# Add or update in the check section:
Check-RegistrySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\Policies" `
    -Name "RestrictUserPrinterInstallation" `
    -ExpectedValue 1 `
    -Description "EnableDevicesPreventUsersFromInstallingPrinterDrivers"

# Checking Edge Hardening Settings...
Write-Host "Checking Edge Hardening Settings..." -ForegroundColor Cyan
Check-EdgeHardeningSettings -Description "EdgeHardeningPolicies"

# Checking Other Folder Settings...
Write-Host "Checking Other Folder Settings..." -ForegroundColor Cyan
Check-OtherFolderSettings -Description "OtherFolderPolicies"

# Checking Remote Access Security Settings...
Write-Host "Checking Remote Access Security Settings..." -ForegroundColor Cyan
Check-RemoteAccessSecuritySettings -Description "RemoteAccessSecuritySettings"

# Checking System Hardening Settings...
Write-Host "Checking System Hardening Settings..." -ForegroundColor Cyan
Check-SystemHardeningPolicies -Description "SystemHardeningPolicies"

# Checking User Account Security Settings...
Write-Host "Checking User Account Security Settings..." -ForegroundColor Cyan
Check-UserAccountSecurityPolicies -Description "UserAccountSecurityPolicies"

# Checking Internet Access Restrictions...
Write-Host "Checking Internet Access Restrictions..." -ForegroundColor Cyan
Check-InternetAccessRestrictions -Description "InternetAccessRestrictions"

# Check if path exists
Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"

# Check the value
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "AllowAdminInstall"

# Calculate compliance percentage
$compliancePercentage = [math]::Round(($passedChecks / $totalChecks) * 100, 2)

# Format the results into the requested string format
$formattedResults = ($results | ForEach-Object {
    $status = if ($_.Status -eq "Not Applied") { "Policy Not Applied" } else { $_.Status }
    $details = $_.Details -replace ',\s*', ','
    
    # Format each result exactly like the example
    "PolicyName:$($_.Description)~CurrentStatus:$status~Details:$details"
}) -join '|'

# Write results to file (single line)
$formattedResults | Out-File -FilePath $resultsFile -NoNewline -Encoding utf8


Remove-Item -Path $auditpolFile -Force -ErrorAction SilentlyContinue

Write-Host "Security check completed. Results saved to: $resultsFile"
Write-Host "Compliance Score: $compliancePercentage% ($passedChecks/$totalChecks checks passed)"
