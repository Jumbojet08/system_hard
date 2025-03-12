$resultsFile = "C:\Users\082820\Downloads\SecurityCheckResults.txt"
$auditpolFile = "C:\Windows\Temp\auditpol.txt"

# Create results array
$results = @()
$totalChecks = 0
$passedChecks = 0

# Function to add result to results array
function Add-Result {
    param (
        [string]$Description,
        [string]$Status,
        [string]$Details = ""
    )
    
    $global:totalChecks++
    if ($Status -eq "Applied") {
        $global:passedChecks++
    }
    
    $result = [PSCustomObject]@{
        Description = $Description
        Status = $Status
        Details = $Details
    }
    
    $global:results += $result
}

# Function to check registry setting
function Check-RegistrySetting {
    param (
        [string]$Path,
        [string]$Name,
        [object]$ExpectedValue,
        [string]$Description
    )
    
    try {
        if (Test-Path -Path $Path) {
            $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            
            if ($null -ne $value) {
                $actualValue = $value.$Name
                $details = "Expected: $ExpectedValue, Found: $actualValue"
                
                if ($actualValue -eq $ExpectedValue) {
                    Add-Result -Description $Description -Status "Applied" -Details $details
                } else {
                    Add-Result -Description $Description -Status "Not Applied" -Details $details
                }
            } else {
                Add-Result -Description $Description -Status "Not Found" -Details "Setting name not found in registry"
            }
        } else {
            Add-Result -Description $Description -Status "Not Found" -Details "Registry path not found"
        }
    } catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking registry: $_"
    }
}

# Function to check local security policy
function Check-SecurityPolicy {
    param (
        [string]$PolicyArea,
        [string]$PolicyName,
        [string]$ExpectedValue,
        [string]$Description
    )
    
    try {
        # Use secedit to export just the requested area
        $tempFile = "C:\Windows\Temp\secedit_$($PolicyArea).txt"
        secedit /export /areas $PolicyArea /cfg $tempFile | Out-Null
        
        if (Test-Path $tempFile) {
            $content = Get-Content -Path $tempFile -Raw
            
            if ($content -match "$PolicyName\s*=\s*(.+)") {
                $actualValue = $matches[1].Trim()
                $details = "Expected: $ExpectedValue, Found: $actualValue"
                
                if ($actualValue -eq $ExpectedValue) {
                    Add-Result -Description $Description -Status "Applied" -Details $details
                } else {
                    Add-Result -Description $Description -Status "Not Applied" -Details $details
                }
            } else {
                Add-Result -Description $Description -Status "Not Found" -Details "Policy not found in security configuration"
            }
            
            Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
        } else {
            Add-Result -Description $Description -Status "Error" -Details "Failed to export security policy area"
        }
    } catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking security policy: $_"
    }
}

# Function to check group policy setting
function Check-GroupPolicy {
    param (
        [string]$GPOPath,
        [string]$ExpectedValue,
        [string]$Description
    )
    
    try {
        # Use gpresult to get applied policies
        $tempFile = "C:\Windows\Temp\gpresult.txt"
        gpresult /f /scope computer > $tempFile
        
        if (Test-Path $tempFile) {
            $content = Get-Content -Path $tempFile -Raw
            
            if ($content -match [regex]::Escape($GPOPath) + ".*?:\s*(.+)") {
                $actualValue = $matches[1].Trim()
                $details = "Expected: $ExpectedValue, Found: $actualValue"
                
                if ($actualValue -match $ExpectedValue) {
                    Add-Result -Description $Description -Status "Applied" -Details $details
                } else {
                    Add-Result -Description $Description -Status "Not Applied" -Details $details
                }
            } else {
                Add-Result -Description $Description -Status "Not Found" -Details "Group Policy setting not found"
            }
            
            Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
        } else {
            Add-Result -Description $Description -Status "Error" -Details "Failed to retrieve Group Policy results"
        }
    } catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking Group Policy: $_"
    }
}

# Function to check if a service is disabled
function Check-ServiceDisabled {
    param (
        [string]$ServiceName,
        [string]$Description
    )
    
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        
        if ($null -eq $service) {
            Add-Result -Description $Description -Status "Not Installed" -Details "Service is not installed"
        } else {
            $status = $service.StartType
            $details = "Current status: $status"
            
            if ($status -eq "Disabled") {
                Add-Result -Description $Description -Status "Applied" -Details $details
            } else {
                Add-Result -Description $Description -Status "Not Applied" -Details $details
            }
        }
    } catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking service: $_"
    }
}

# Function to check for USB storage restrictions using registry
function Check-USBStorageRestrictions {
    param (
        [string]$Description
    )
    
    try {
        # Check multiple methods of USB storage restriction
        $methodsChecked = @()
        $methodsApplied = @()
        
        # Method 1: Check if USBSTOR service is disabled
        $usbstorService = Get-Service -Name "USBSTOR" -ErrorAction SilentlyContinue
        $methodsChecked += "USBSTOR Service"
        if ($null -ne $usbstorService -and $usbstorService.StartType -eq "Disabled") {
            $methodsApplied += "USBSTOR Service Disabled"
        }
        
        # Method 2: Check Group Policy for USB storage device restriction
        $gpoPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\Deny_All"
        $denyAll = Get-ItemProperty -Path $gpoPath -Name "Deny" -ErrorAction SilentlyContinue
        $methodsChecked += "Group Policy Restriction"
        if ($null -ne $denyAll -and $denyAll.Deny -eq 1) {
            $methodsApplied += "Group Policy Restriction Applied"
        }
        
        # Method 3: Check device installation restrictions
        $deviceInstallPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
        $denyDeviceInstall = Get-ItemProperty -Path $deviceInstallPath -Name "DenyRemovableDevices" -ErrorAction SilentlyContinue
        $methodsChecked += "Device Installation Restriction"
        if ($null -ne $denyDeviceInstall -and $denyDeviceInstall.DenyRemovableDevices -eq 1) {
            $methodsApplied += "Device Installation Restriction Applied"
        }
        
        if ($methodsApplied.Count -gt 0) {
            Add-Result -Description $Description -Status "Applied" -Details "Restrictions found: $($methodsApplied -join ", ")"
        } else {
            Add-Result -Description $Description -Status "Not Applied" -Details "No USB storage restrictions found. Methods checked: $($methodsChecked -join ", ")"
        }
    } catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking USB restrictions: $_"
    }
}

# Function to check for CD-ROM restrictions using registry
function Check-CDROMRestrictions {
    param (
        [string]$Description
    )
    
    try {
        # Check multiple methods of CD-ROM restriction
        $methodsChecked = @()
        $methodsApplied = @()
        
        # Method 1: Check CD-ROM service startup type
        $cdromService = Get-Service -Name "cdrom" -ErrorAction SilentlyContinue
        $methodsChecked += "CDROM Service"
        if ($null -ne $cdromService -and $cdromService.StartType -eq "Disabled") {
            $methodsApplied += "CDROM Service Disabled"
        }
        
        # Method 2: Check Group Policy for CD-ROM restriction
        $gpoPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\CD-ROM"
        $denyCD = Get-ItemProperty -Path $gpoPath -Name "Deny" -ErrorAction SilentlyContinue
        $methodsChecked += "Group Policy Restriction"
        if ($null -ne $denyCD -and $denyCD.Deny -eq 1) {
            $methodsApplied += "Group Policy Restriction Applied"
        }
        
        # Method 3: Check for access restriction via registry
        $accessPath = "HKLM\SYSTEM\CurrentControlSet\Services\cdrom\Parameters"
        $autorun = Get-ItemProperty -Path $accessPath -Name "AutoRun" -ErrorAction SilentlyContinue
        $methodsChecked += "Registry Access Restriction"
        if ($null -ne $autorun -and $autorun.AutoRun -eq 0) {
            $methodsApplied += "Registry Access Restriction Applied"
        }
        
        if ($methodsApplied.Count -gt 0) {
            Add-Result -Description $Description -Status "Applied" -Details "Restrictions found: $($methodsApplied -join ", ")"
        } else {
            Add-Result -Description $Description -Status "Not Applied" -Details "No CD-ROM restrictions found. Methods checked: $($methodsChecked -join ", ")"
        }
    } catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking CD-ROM restrictions: $_"
    }
}

# Function to check for unnecessary programs
function Check-UnnecessaryPrograms {
    param (
        [string]$Description
    )
    
    try {
        $unwantedPrograms = @(
            "TeamViewer", "uTorrent", "AnyDesk", "Skype", "Zoom", 
            "BitTorrent", "Limewire", "TorrentClient", "Remote Utilities",
            "LogMeIn", "Chrome Remote Desktop", "VNC", "TightVNC", "UltraVNC"
        )
        
        $installed = @()
        $installed += Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | 
                     Where-Object DisplayName -ne $null | 
                     Select-Object DisplayName
        $installed += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | 
                     Where-Object DisplayName -ne $null | 
                     Select-Object DisplayName
        
        $found = @($installed | Where-Object { $unwantedPrograms -contains $_.DisplayName })
        
        if ($found.Count -eq 0) {
            Add-Result -Description $Description -Status "Applied" -Details "No unnecessary programs found"
        } else {
            $programList = ($found.DisplayName -join ", ")
            Add-Result -Description $Description -Status "Not Applied" -Details "Found: $programList"
        }
    } catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking programs: $_"
    }
}

# Function to check user accounts
function Check-UserAccounts {
    param (
        [string]$Description,
        [string]$AccountType
    )
    
    try {
        if ($AccountType -eq "Admin") {
            # Use ADSI instead of Get-LocalGroupMember
            $adminGroup = [ADSI]"WinNT://$env:COMPUTERNAME/Administrators"
            $adminUsers = @()
            
            $adminGroup.Members() | ForEach-Object {
                try {
                    $adminUsers += $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
                } catch {
                    # Skip failed member retrievals
                }
            }
            
            Add-Result -Description $Description -Status "Applied" -Details "Found $($adminUsers.Count) admin users"
        }
        elseif ($AccountType -eq "Standard") {
            # Get all local users
            $allUsers = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'"
            $adminGroup = [ADSI]"WinNT://$env:COMPUTERNAME/Administrators"
            $adminUsers = @()
            
            $adminGroup.Members() | ForEach-Object {
                try {
                    $adminUsers += $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
                } catch {
                    # Skip failed member retrievals
                }
            }
            
            $standardUsers = $allUsers | Where-Object { $adminUsers -notcontains $_.Name -and $_.Disabled -eq $false }
            Add-Result -Description $Description -Status "Applied" -Details "Found $($standardUsers.Count) enabled standard users"
        }
    } catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking user accounts: $_"
    }
}

# Function to check if built-in admin is renamed
function Check-AdminRenamed {
    param (
        [string]$Description
    )
    
    try {
        # Use WMI to find built-in administrator account (SID ending in 500)
        $adminAccount = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True' AND SID LIKE '%-500'"
        
        if ($null -eq $adminAccount) {
            Add-Result -Description $Description -Status "Error" -Details "Could not find built-in administrator account"
        } else {
            if ($adminAccount.Name -eq "Administrator") {
                Add-Result -Description $Description -Status "Not Applied" -Details "Built-in administrator account not renamed"
            } else {
                Add-Result -Description $Description -Status "Applied" -Details "Built-in administrator account renamed to: $($adminAccount.Name)"
            }
        }
    } catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking admin account: $_"
    }
}

# Function to check if guest account is disabled
function Check-GuestDisabled {
    param (
        [string]$Description
    )
    
    try {
        # Use WMI to find built-in guest account (SID ending in 501)
        $guestAccount = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True' AND SID LIKE '%-501'"
        
        if ($null -eq $guestAccount) {
            Add-Result -Description $Description -Status "Error" -Details "Could not find built-in guest account"
        } else {
            if ($guestAccount.Disabled) {
                Add-Result -Description $Description -Status "Applied" -Details "Guest account is disabled"
            } else {
                Add-Result -Description $Description -Status "Not Applied" -Details "Guest account is enabled"
            }
        }
    } catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking guest account: $_"
    }
}

# Function to check network adapters
function Check-NetworkAdapters {
    param (
        [string]$Description
    )
    
    try {
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        $disabledAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Disabled" }
        
        if ($adapters.Count -eq 0) {
            Add-Result -Description $Description -Status "Error" -Details "No network adapters are up (system would be inaccessible)"
        } else {
            $unusedAdapters = $adapters | Where-Object { $_.MediaConnectionState -eq "Disconnected" }
            
            if ($unusedAdapters.Count -eq 0) {
                Add-Result -Description $Description -Status "Applied" -Details "No unused adapters found in 'Up' state"
            } else {
                Add-Result -Description $Description -Status "Not Applied" -Details "Found $($unusedAdapters.Count) disconnected adapters still enabled"
            }
        }
    } catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking network adapters: $_"
    }
}

# Function to check firewall status
function Check-Firewall {
    param (
        [string]$Description
    )
    
    try {
        $firewallProfiles = Get-NetFirewallProfile
        $enabledProfiles = $firewallProfiles | Where-Object { $_.Enabled -eq $true }
        
        if ($enabledProfiles.Count -eq $firewallProfiles.Count) {
            Add-Result -Description $Description -Status "Applied" -Details "All firewall profiles are enabled"
        } else {
            $disabledProfiles = ($firewallProfiles | Where-Object { $_.Enabled -eq $false }).Name -join ", "
            Add-Result -Description $Description -Status "Not Applied" -Details "Disabled profiles: $disabledProfiles"
        }
    } catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking firewall: $_"
    }
}

# Function to check password policies
function Check-PasswordPolicies {
    param (
        [string]$Description
    )
    
    try {
        # Use net accounts to get password policy
        $passwordPolicyOutput = net accounts
        
        # Extract relevant settings using regex
        $minLength = if ($passwordPolicyOutput -match "Minimum password length\s+:\s+(\d+)") { [int]$Matches[1] } else { 0 }
        $maxAge = if ($passwordPolicyOutput -match "Maximum password age \(days\)\s+:\s+(\d+)") { [int]$Matches[1] } else { 0 }
        $minAge = if ($passwordPolicyOutput -match "Minimum password age \(days\)\s+:\s+(\d+)") { [int]$Matches[1] } else { 0 }
        $history = if ($passwordPolicyOutput -match "Length of password history maintained\s+:\s+(\d+)") { [int]$Matches[1] } else { 0 }
        $lockoutThreshold = if ($passwordPolicyOutput -match "Lockout threshold\s+:\s+(\d+|Never)") { $Matches[1] } else { "Unknown" }
        
        # Check complexity using registry
        $complexityPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $complexity = (Get-ItemProperty -Path $complexityPath -Name "PasswordComplexity" -ErrorAction SilentlyContinue).PasswordComplexity
        $complexityStatus = if ($complexity -eq 1) { "Enabled" } else { "Disabled" }
        
        # Determine if policies meet requirements (adjust thresholds as needed)
        $details = "Min Length: $minLength, Max Age: $maxAge, Min Age: $minAge, History: $history, Lockout: $lockoutThreshold, Complexity: $complexityStatus"
        
        if ($minLength -ge 12 -and $maxAge -le 90 -and $minAge -ge 1 -and $history -ge 5 -and $lockoutThreshold -ne "Never" -and $complexity -eq 1) {
            Add-Result -Description $Description -Status "Applied" -Details $details
        } else {
            Add-Result -Description $Description -Status "Not Applied" -Details $details
        }
    } catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking password policies: $_"
    }
}

# Function to check security software
function Check-SecuritySoftware {
    param (
        [string]$Description
    )
    
    try {
        # Check for antivirus using multiple methods
        $avFound = $false
        $avName = "None"
        
        # Method 1: Check Windows Security Center
        try {
            $avProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction SilentlyContinue
            if ($null -ne $avProducts -and $avProducts.Count -gt 0) {
                $avFound = $true
                $avName = ($avProducts | ForEach-Object { $_.displayName }) -join ", "
            }
        } catch {
            # Continue to next method if this fails
        }
        
        # Method 2: Check Windows Defender status if no other AV found
        if (-not $avFound) {
            $defenderPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender"
            $defenderStatus = Get-ItemProperty -Path $defenderPath -ErrorAction SilentlyContinue
            
            if ($null -ne $defenderStatus) {
                $avFound = $true
                $avName = "Windows Defender"
            }
        }
        
        # Check for application whitelisting (AppLocker or WDAC)
        $whitelistingFound = $false
        $whitelistingName = "None"
        
        # Check AppLocker
        $appLockerService = Get-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
        $appLockerPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2"
        
        if (($null -ne $appLockerService -and $appLockerService.Status -eq "Running") -or 
            (Test-Path $appLockerPath)) {
            $whitelistingFound = $true
            $whitelistingName = "AppLocker"
        }
        
        # Check WDAC (Windows Defender Application Control)
        $wdacPolicies = Get-ChildItem -Path "C:\Windows\System32\CodeIntegrity\CiPolicies\Active\" -ErrorAction SilentlyContinue
        if ($null -ne $wdacPolicies -and $wdacPolicies.Count -gt 0) {
            $whitelistingFound = $true
            $whitelistingName = "Windows Defender Application Control"
        }
        
        if ($avFound -and $whitelistingFound) {
            Add-Result -Description $Description -Status "Applied" -Details "AV: $avName, Application Whitelisting: $whitelistingName"
        } else {
            $missing = @()
            if (-not $avFound) { $missing += "Antivirus" }
            if (-not $whitelistingFound) { $missing += "Application Whitelisting" }
            
            Add-Result -Description $Description -Status "Not Applied" -Details "Missing: $($missing -join ", "). Found: AV: $avName, Whitelisting: $whitelistingName"
        }
    } catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking security software: $_"
    }
}

# Function to check auditing policies
function Check-AuditingPolicies {
    param (
        [string]$Description
    )
    
    try {
        # Use PowerShell to check audit policies
        $categories = @(
            "Account Logon",
            "Account Management",
            "Logon/Logoff",
            "Object Access",
            "Policy Change",
            "Privilege Use",
            "System"
        )
        
        $missingPolicies = @()
        
        foreach ($category in $categories) {
            $result = auditpol /get /category:$category 2>$null
            if ($result -notmatch "Success and Failure") {
                $missingPolicies += $category
            }
        }
        
        if ($missingPolicies.Count -eq 0) {
            Add-Result -Description $Description -Status "Applied" -Details "All required audit policies are configured"
        } else {
            Add-Result -Description $Description -Status "Not Applied" -Details "Missing policies: $($missingPolicies -join ', ')"
        }
    } catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking audit policies: $_"
    }
}

# Function to check non-interactive service accounts
function Check-ServiceAccounts {
    param (
        [string]$Description
    )
    
    try {
        $serviceAccounts = Get-WmiObject -Class Win32_Service | 
            Where-Object { $_.StartName -notmatch 'LocalSystem|NT AUTHORITY|NT SERVICE' -and $_.StartName -ne "" } | 
            Select-Object DisplayName, StartName
        
        if ($serviceAccounts.Count -eq 0) {
            Add-Result -Description $Description -Status "Not Applicable" -Details "No custom service accounts found"
        } else {
            # Check if these accounts are in the "Deny log on locally" security setting
            $denyLogonPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            $denyLogonAccounts = (Get-ItemProperty -Path $denyLogonPath -Name "DenyLogonLocallyName" -ErrorAction SilentlyContinue).DenyLogonLocallyName
            
            $nonCompliantAccounts = @()
            foreach ($account in $serviceAccounts) {
                $accountName = ($account.StartName -split '\\')[-1]
                if ($null -eq $denyLogonAccounts -or $denyLogonAccounts -notcontains $accountName) {
                    $nonCompliantAccounts += "$($account.DisplayName) ($($account.StartName))"
                }
            }
            
            if ($nonCompliantAccounts.Count -eq 0) {
                Add-Result -Description $Description -Status "Applied" -Details "All service accounts are restricted from interactive login"
            } else {
                Add-Result -Description $Description -Status "Not Applied" -Details "Service accounts not restricted: $($nonCompliantAccounts -join ", ")"
            }
        }
    } catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking service accounts: $_"
    }
}

# Function to check NTP configuration
function Check-NTPConfiguration {
    param (
        [string]$Description
    )
    
    try {
        # Check Windows Time service
        $timeService = Get-Service -Name "W32Time" -ErrorAction SilentlyContinue
        
        # Get NTP settings using registry
        $ntpParams = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -ErrorAction SilentlyContinue
        $ntpConfig = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config" -ErrorAction SilentlyContinue
        
        $details = @()
        
        # Check service status
        if ($timeService) {
            $details += "Service Status: $($timeService.Status)"
        } else {
            $details += "Service Status: Not Found"
        }
        
        # Check NTP server
        if ($ntpParams.NtpServer) {
            $details += "NTP Server: $($ntpParams.NtpServer)"
        } else {
            $details += "NTP Server: Not Configured"
        }
        
        # Check sync type
        if ($ntpParams.Type) {
            $details += "Sync Type: $($ntpParams.Type)"
        }
        
        # Get current time source
        $w32tmStatus = w32tm /query /status /verbose 2>$null
        if ($w32tmStatus) {
            $source = ($w32tmStatus | Select-String "Source:.*").ToString()
            if ($source) {
                $details += $source
            }
        }
        
        if ($timeService.Status -eq 'Running' -and $ntpParams.NtpServer) {
            Add-Result -Description $Description -Status "Applied" -Details ($details -join ", ")
        } else {
            Add-Result -Description $Description -Status "Not Applied" -Details ($details -join ", ")
        }
    } catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking NTP: $_"
    }
}

# Function to check User Account Control settings via registry
function Check-UACSettings {
    param (
        [string]$Description,
        [string]$RegistryName,
        [int]$ExpectedValue
    )
    
    try {
        $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $actualValue = (Get-ItemProperty -Path $uacPath -Name $RegistryName -ErrorAction SilentlyContinue).$RegistryName
        
        if ($null -eq $actualValue) {
            Add-Result -Description $Description -Status "Not Found" -Details "Setting not found in registry"
        } else {
            $details = "Expected: $ExpectedValue, Found: $actualValue"
            
            if ($actualValue -eq $ExpectedValue) {
                Add-Result -Description $Description -Status "Applied" -Details $details
            } else {
                Add-Result -Description $Description -Status "Not Applied" -Details $details
            }
        }
    } catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking UAC setting: $_"
    }
}

# Function to check autorun settings
function Check-AutorunSettings {
    param (
        [string]$Description
    )
    
    try {
        $autorunPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        $autorunValue = (Get-ItemProperty -Path $autorunPath -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue).NoDriveTypeAutoRun
        
        if ($null -eq $autorunValue) {
            Add-Result -Description $Description -Status "Not Found" -Details "Autorun setting not found in registry"
        } else {
            $details = "Expected: 255 (all drives), Found: $autorunValue"
            
            if ($autorunValue -eq 255) {
                Add-Result -Description $Description -Status "Applied" -Details $details
            } else {
                Add-Result -Description $Description -Status "Not Applied" -Details $details
            }
        }
    } catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking autorun settings: $_"
    }
}
# Function to check security policy settings related to interactive logon
function Check-InteractiveLogonPolicy {
    param (
        [string]$PolicyName,
        [string]$ExpectedValue,
        [string]$Description
    )
    
    try {
        # Convert registry path to proper format
        $regPath = $PolicyName -replace '^MACHINE\\', 'HKLM:\\'
        
        # Get the registry value directly instead of using secedit
        try {
            $keyPath = Split-Path -Path $regPath
            $valueName = Split-Path -Path $regPath -Leaf
            
            $actualValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction Stop).$valueName
            $details = "Expected: $ExpectedValue, Found: $actualValue"
            
            if ($actualValue.ToString() -eq $ExpectedValue) {
                Add-Result -Description $Description -Status "Applied" -Details $details
            } else {
                Add-Result -Description $Description -Status "Not Applied" -Details $details
            }
        }
        catch {
            Add-Result -Description $Description -Status "Not Found" -Details "Policy setting not found in registry"
        }
    } catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking security policy: $_"
    }
}

# Function to check user right assignments
function Check-UserRightAssignment {
    param (
        [string]$RightName,
        [string]$Description,
        [string[]]$AllowedAccounts = @(),
        [bool]$ShouldBeEmpty = $false
    )
    
    try {
        # Use secedit to export user rights
        $tempFile = "C:\Windows\Temp\secedit_rights.txt"
        secedit /export /areas USER_RIGHTS /cfg $tempFile | Out-Null
        
        if (Test-Path $tempFile) {
            $content = Get-Content -Path $tempFile -Raw
            
            if ($content -match "$RightName\s*=\s*(.+)") {
                $accounts = $matches[1].Trim().Split(',').Trim()
                $details = "Accounts with this right: $($accounts -join ', ')"
                
                if ($ShouldBeEmpty -and $accounts.Count -eq 0) {
                    Add-Result -Description $Description -Status "Applied" -Details "No accounts have this right"
                } 
                elseif ($ShouldBeEmpty -and $accounts.Count -gt 0) {
                    Add-Result -Description $Description -Status "Not Applied" -Details $details
                }
                elseif (-not $ShouldBeEmpty -and $AllowedAccounts.Count -gt 0) {
                    $unauthorized = $accounts | Where-Object { $AllowedAccounts -notcontains $_ }
                    
                    if ($unauthorized.Count -eq 0) {
                        Add-Result -Description $Description -Status "Applied" -Details "Only authorized accounts have this right"
                    } else {
                        Add-Result -Description $Description -Status "Not Applied" -Details "Unauthorized accounts: $($unauthorized -join ', ')"
                    }
                } else {
                    Add-Result -Description $Description -Status "Applied" -Details $details
                }
            } else {
                Add-Result -Description $Description -Status "Not Found" -Details "User right not found in security configuration"
            }
            
            Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
        } else {
            Add-Result -Description $Description -Status "Error" -Details "Failed to export user rights"
        }
    } catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking user rights: $_"
    }
}

# Function to check NTLM and LAN Manager settings
function Check-NTLMSettings {
    param (
        [string]$Description
    )
    
    try {
        $ntlmPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $lmCompatLevel = (Get-ItemProperty -Path $ntlmPath -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue).LmCompatibilityLevel
        $storeLMHash = (Get-ItemProperty -Path $ntlmPath -Name "NoLMHash" -ErrorAction SilentlyContinue).NoLMHash
        
        $details = "LM Compatibility Level: $lmCompatLevel, Don't store LM hash: $storeLMHash"
        
        # Level 5 = Send NTLMv2 only, refuse LM & NTLM
        # NoLMHash = 1 means don't store LM hash on password change
        if ($lmCompatLevel -ge 3 -and $storeLMHash -eq 1) {
            Add-Result -Description $Description -Status "Applied" -Details $details
        } else {
            Add-Result -Description $Description -Status "Not Applied" -Details $details
        }
    } catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking NTLM settings: $_"
    }
}

# Function to check additional UAC settings
function Check-AdditionalUACSettings {
    param (
        [string]$RegistryName,
        [string]$Description,
        [int]$ExpectedValue
    )
    
    try {
        $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $actualValue = (Get-ItemProperty -Path $uacPath -Name $RegistryName -ErrorAction SilentlyContinue).$RegistryName
        
        if ($null -eq $actualValue) {
            Add-Result -Description $Description -Status "Not Found" -Details "Setting not found in registry"
        } else {
            $details = "Expected: $ExpectedValue, Found: $actualValue"
            
            if ($actualValue -eq $ExpectedValue) {
                Add-Result -Description $Description -Status "Applied" -Details $details
            } else {
                Add-Result -Description $Description -Status "Not Applied" -Details $details
            }
        }
    } catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking UAC setting: $_"
    }
}

# Function to check Recovery Console settings
function Check-RecoveryConsoleSettings {
    param (
        [string]$Description
    )
    
    try {
        $recoveryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole"
        $autoAdminLogon = (Get-ItemProperty -Path $recoveryPath -Name "SecurityLevel" -ErrorAction SilentlyContinue).SecurityLevel
        
        if ($null -eq $autoAdminLogon) {
            Add-Result -Description $Description -Status "Not Found" -Details "Recovery console setting not found"
        } else {
            $details = "Expected: 0 (Disabled), Found: $autoAdminLogon"
            
            if ($autoAdminLogon -eq 0) {
                Add-Result -Description $Description -Status "Applied" -Details $details
            } else {
                Add-Result -Description $Description -Status "Not Applied" -Details $details
            }
        }
    } catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking Recovery Console settings: $_"
    }
}

# Function to check anonymous enumeration settings
function Check-AnonymousEnumeration {
    param (
        [string]$Description
    )
    
    try {
        $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $restrictAnonymous = (Get-ItemProperty -Path $lsaPath -Name "RestrictAnonymous" -ErrorAction SilentlyContinue).RestrictAnonymous
        $restrictAnonymousSAM = (Get-ItemProperty -Path $lsaPath -Name "RestrictAnonymousSAM" -ErrorAction SilentlyContinue).RestrictAnonymousSAM
        
        $details = "Restrict Anonymous: $restrictAnonymous, Restrict Anonymous SAM: $restrictAnonymousSAM"
        
        if ($restrictAnonymous -eq 1 -and $restrictAnonymousSAM -eq 1) {
            Add-Result -Description $Description -Status "Applied" -Details $details
        } else {
            Add-Result -Description $Description -Status "Not Applied" -Details $details
        }
    } catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking anonymous enumeration settings: $_"
    }
}

# Function to check logon banner settings
function Check-LogonBanner {
    param (
        [string]$Description
    )
    
    try {
        $bannerPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $legalNoticeCaption = (Get-ItemProperty -Path $bannerPath -Name "legalnoticecaption" -ErrorAction SilentlyContinue).legalnoticecaption
        $legalNoticeText = (Get-ItemProperty -Path $bannerPath -Name "legalnoticetext" -ErrorAction SilentlyContinue).legalnoticetext
        
        if ($null -eq $legalNoticeCaption -or $null -eq $legalNoticeText -or $legalNoticeCaption -eq "" -or $legalNoticeText -eq "") {
            Add-Result -Description $Description -Status "Not Applied" -Details "Logon banner not configured"
        } else {
            $details = "Banner Title: $legalNoticeCaption"
            Add-Result -Description $Description -Status "Applied" -Details $details
        }
    } catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking logon banner: $_"
    }
}

# Function to check network security settings
function Check-NetworkSecuritySettings {
    param (
        [string]$Description
    )
    
    try {
        $securityPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
        $ntlmPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
        
        # Check digital signing
        $requireSign = (Get-ItemProperty -Path $securityPath -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue).RequireSecuritySignature
        
        # Check NTLM SSP security
        $ntlmSecurity = (Get-ItemProperty -Path $ntlmPath -Name "NTLMMinClientSec" -ErrorAction SilentlyContinue).NTLMMinClientSec
        
        $details = @()
        $details += "Digital Signing Required: $($requireSign -eq 1)"
        $details += "NTLM Min Security: $ntlmSecurity"
        
        if ($requireSign -eq 1 -and $ntlmSecurity -ge 537395200) {
            Add-Result -Description $Description -Status "Applied" -Details ($details -join ", ")
        } else {
            Add-Result -Description $Description -Status "Not Applied" -Details ($details -join ", ")
        }
    } catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking network security settings: $_"
    }
}

# Function to check device installation settings
function Check-DeviceInstallationSettings {
    param (
        [string]$Description
    )
    
    try {
        $devicePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
        
        $adminOverride = (Get-ItemProperty -Path $devicePath -Name "AllowAdminInstall" -ErrorAction SilentlyContinue).AllowAdminInstall
        $customMessage = (Get-ItemProperty -Path $devicePath -Name "DenyMessageText" -ErrorAction SilentlyContinue).DenyMessageText
        $customTitle = (Get-ItemProperty -Path $devicePath -Name "DenyMessageTitle" -ErrorAction SilentlyContinue).DenyMessageTitle
        
        $details = @(
            "Admin Override: $($adminOverride -eq 1)",
            "Custom Message Configured: $(-not [string]::IsNullOrEmpty($customMessage))",
            "Custom Title Configured: $(-not [string]::IsNullOrEmpty($customTitle))"
        )
        
        if ($adminOverride -eq 1 -and -not [string]::IsNullOrEmpty($customMessage) -and -not [string]::IsNullOrEmpty($customTitle)) {
            Add-Result -Description $Description -Status "Applied" -Details ($details -join ", ")
        } else {
            Add-Result -Description $Description -Status "Not Applied" -Details ($details -join ", ")
        }
    } catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking device installation settings: $_"
    }
}

# Function to check removable storage access
function Check-RemovableStorageAccess {
    param (
        [string]$Description
    )
    
    try {
        $storagePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices"
        
        $denyAll = (Get-ItemProperty -Path "$storagePath\Deny_All" -Name "Deny" -ErrorAction SilentlyContinue).Deny
        $denyExecute = (Get-ItemProperty -Path "$storagePath\Deny_Execute" -Name "Deny" -ErrorAction SilentlyContinue).Deny
        $denyCDDVD = (Get-ItemProperty -Path "$storagePath\CD_DVD" -Name "Deny" -ErrorAction SilentlyContinue).Deny
        
        $details = @(
            "All Access Denied: $($denyAll -eq 1)",
            "Execute Denied: $($denyExecute -eq 1)",
            "CD/DVD Denied: $($denyCDDVD -eq 1)"
        )
        
        if ($denyAll -eq 1 -and $denyExecute -eq 1 -and $denyCDDVD -eq 1) {
            Add-Result -Description $Description -Status "Applied" -Details ($details -join ", ")
        } else {
            Add-Result -Description $Description -Status "Not Applied" -Details ($details -join ", ")
        }
    } catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking removable storage settings: $_"
    }
}

# Function to check network settings
function Check-NetworkSettings {
    param (
        [string]$Description
    )
    
    try {
        # Check LLMNR setting
        $llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        $llmnrDisabled = (Get-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -ErrorAction SilentlyContinue).EnableMulticast -eq 0
        
        # Check Remote Assistance
        $raPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"
        $raDisabled = (Get-ItemProperty -Path $raPath -Name "fAllowToGetHelp" -ErrorAction SilentlyContinue).fAllowToGetHelp -eq 0
        
        # Check IPv6
        $adapters = Get-NetAdapter | Where-Object Status -eq "Up"
        $ipv6Disabled = $true
        foreach ($adapter in $adapters) {
            if ((Get-NetAdapterBinding -InterfaceAlias $adapter.Name -ComponentID "ms_tcpip6").Enabled) {
                $ipv6Disabled = $false
                break
            }
        }
        
        # Check NetBIOS
        $netbiosDisabled = $true
        foreach ($adapter in $adapters) {
            $netbiosSetting = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.Index -eq $adapter.ifIndex }
            if ($netbiosSetting.TcpipNetbiosOptions -ne 2) {
                $netbiosDisabled = $false
                break
            }
        }
        
        $details = @(
            "LLMNR Disabled: $llmnrDisabled",
            "Remote Assistance Disabled: $raDisabled",
            "IPv6 Disabled: $ipv6Disabled",
            "NetBIOS Disabled: $netbiosDisabled"
        )
        
        if ($llmnrDisabled -and $raDisabled -and $ipv6Disabled -and $netbiosDisabled) {
            Add-Result -Description $Description -Status "Applied" -Details ($details -join ", ")
        } else {
            Add-Result -Description $Description -Status "Not Applied" -Details ($details -join ", ")
        }
    } catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking network settings: $_"
    }
}

# Function to check PowerShell settings
function Check-PowerShellSettings {
    param (
        [string]$Description
    )
    
    try {
        $psPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
        
        # Check Module Logging
        $moduleLogging = (Get-ItemProperty -Path "$psPath\ModuleLogging" -Name "EnableModuleLogging" -ErrorAction SilentlyContinue).EnableModuleLogging
        
        # Check Script Block Logging
        $scriptBlockLogging = (Get-ItemProperty -Path "$psPath\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging
        
        # Check Transcription
        $transcription = (Get-ItemProperty -Path "$psPath\Transcription" -Name "EnableTranscripting" -ErrorAction SilentlyContinue).EnableTranscripting
        
        # Check PSLockdownPolicy
        $lockdownPolicy = [Environment]::GetEnvironmentVariable("PSLockdownPolicy", "Machine")
        
        $details = @(
            "Module Logging: $($moduleLogging -eq 1)",
            "Script Block Logging: $($scriptBlockLogging -eq 1)",
            "Transcription: $($transcription -eq 1)",
            "Lockdown Policy: $lockdownPolicy"
        )
        
        if ($moduleLogging -eq 1 -and $scriptBlockLogging -eq 1 -and $transcription -eq 1 -and $lockdownPolicy -eq 4) {
            Add-Result -Description $Description -Status "Applied" -Details ($details -join ", ")
        } else {
            Add-Result -Description $Description -Status "Not Applied" -Details ($details -join ", ")
        }
    } catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking PowerShell settings: $_"
    }
}

# Function to check SMB settings
function Check-SMBSettings {
    param (
        [string]$Description
    )
    
    try {
        $smbPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        $smbv1Enabled = (Get-ItemProperty -Path $smbPath -Name "SMB1" -ErrorAction SilentlyContinue).SMB1
        
        if ($null -eq $smbv1Enabled -or $smbv1Enabled -eq 0) {
            Add-Result -Description $Description -Status "Applied" -Details "SMB v1 is disabled"
        } else {
            Add-Result -Description $Description -Status "Not Applied" -Details "SMB v1 is enabled"
        }
    } catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking SMB settings: $_"
    }
}

# Function to check additional security settings
function Check-AdditionalSecuritySettings {
    param (
        [string]$Description
    )
    
    try {
        $results = @()
        
        # Check Internet resource contact settings
        $internetSettings = @{
            "HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" = "RequireMutualAuthentication=1, RequireIntegrity=1"
            "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\Client" = "fEnableInternetPrinting=0"
            "HKLM:\Software\Policies\Microsoft\Windows\DriverSearching" = "SearchOrderConfig=0"
        }
        
        # Machine account and secure channel settings
        $secureChannelPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
        $regSettings = @{
            "RefusePasswordChange" = 1
            "RequireSignOrSeal" = 1
            "RequireStrongKey" = 1
        }
        
        # System and security settings
        $systemPoliciesPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $systemSettings = @{
            "ShutdownWithoutLogon" = 0
            "ConsentPromptBehaviorUser" = 0
            "EnableFontProviders" = 0
        }
        
        # Network and Group Policy settings
        $networkSettingsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnections"
        $networkSettings = @{
            "NC_ShowSharedAccessUI" = 0
            "NC_StdDomainUserSetLocation" = 1
        }
        
        # LLTD settings
        $lltdPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
        $lltdSettings = @{
            "AllowLLTDIO" = 0
            "AllowRspndr" = 0
        }
        
        # HTTP and print settings
        $printPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
        $printSettings = @{
            "DisableWebPnPDownload" = 1
            "DisableHTTPPrinting" = 1
            "RestrictDriverInstallationToAdministrators" = 1
        }
        
        # Point and Print restrictions
        $pointPrintPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
        $pointPrintSettings = @{
            "NoWarningNoElevationOnInstall" = 0
            "UpdatePromptSettings" = 0
            "RestrictDriverInstallationToAdministrators" = 1
        }
        
        # Microsoft connection settings
        $msConnectionPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard"
        $msSettings = @{
            "ExitOnMSICW" = 1
            "DownloadFilesDemand" = 0
        }
        
        # Check each setting
        foreach ($setting in $regSettings.GetEnumerator()) {
            $value = Get-ItemProperty -Path $secureChannelPath -Name $setting.Key -ErrorAction SilentlyContinue
            if ($value -eq $setting.Value) {
                $results += "✓ $($setting.Key) is properly configured"
            } else {
                $results += "✗ $($setting.Key) is not properly configured"
            }
        }
        
        # Check additional settings
        $checks = @(
            @{
                Path = $systemPoliciesPath
                Name = "ShutdownWithoutLogon"
                Expected = 0
                Description = "System shutdown without logon"
            },
            @{
                Path = $lltdPath
                Name = "AllowLLTDIO"
                Expected = 0
                Description = "LLTDIO driver"
            },
            @{
                Path = $lltdPath
                Name = "AllowRspndr"
                Expected = 0
                Description = "RSPNDR driver"
            },
            @{
                Path = $printPath
                Name = "DisableWebPnPDownload"
                Expected = 1
                Description = "Web PnP download"
            }
        )
        
        foreach ($check in $checks) {
            $value = Get-ItemProperty -Path $check.Path -Name $check.Name -ErrorAction SilentlyContinue
            if ($value -eq $check.Expected) {
                $results += "✓ $($check.Description) is properly configured"
            } else {
                $results += "✗ $($check.Description) is not properly configured"
            }
        }
        
        if ($results.Where({$_ -match "✗"}).Count -eq 0) {
            Add-Result -Description $Description -Status "Applied" -Details ($results -join ", ")
        } else {
            Add-Result -Description $Description -Status "Not Applied" -Details ($results -join ", ")
        }
        
    } catch {
        Add-Result -Description $Description -Status "Error" -Details "Error checking additional security settings: $_"
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
Check-AuditingPolicies -Description "Configure auditing and logging"
Check-PasswordPolicies -Description "Configure password policies"
Check-NTPConfiguration -Description "Configure NTP"

# 4. Device and Media Controls
Check-USBStorageRestrictions -Description "Disable USB ports for standard users"
Check-CDROMRestrictions -Description "Disable CD-ROM drives for standard users"
Check-AutorunSettings -Description "Disable 'Autorun' capability for all external media"

# 5. Network Security
Check-Firewall -Description "Enable and configure Windows firewall"
Check-NetworkAdapters -Description "Disable unused network adapters"

# 6. UAC Settings
Check-UACSettings -Description "Enable UAC" -RegistryName "EnableLUA" -ExpectedValue 1
Check-UACSettings -Description "Set UAC to highest level" -RegistryName "ConsentPromptBehaviorAdmin" -ExpectedValue 2
Check-UACSettings -Description "Enable secure desktop" -RegistryName "PromptOnSecureDesktop" -ExpectedValue 1
# New UAC Settings Checks
Check-AdditionalUACSettings -RegistryName "EnableUIADesktopToggle" -Description "Set 'Admin Approval Mode for the built-in Administrator account' to Enabled" -ExpectedValue 1
Check-AdditionalUACSettings -RegistryName "ValidateAdminCodeSignatures" -Description "Set 'Only elevate executables that are signed and validated' to Enabled" -ExpectedValue 1
Check-AdditionalUACSettings -RegistryName "EnableInstallerDetection" -Description "Set 'Detect application installations and prompt for elevation' to Enabled" -ExpectedValue 1
Check-AdditionalUACSettings -RegistryName "EnableSecureUIAPaths" -Description "Set 'Only elevate UIAccess applications that are installed in secure locations' to Enabled" -ExpectedValue 1
Check-AdditionalUACSettings -RegistryName "EnableVirtualization" -Description "Set 'Virtualize file and registry write failures to per-user locations' to Enabled" -ExpectedValue 1
Check-AdditionalUACSettings -RegistryName "ConsentPromptBehaviorUser" -Description "Set 'Behavior of the elevation prompt for standard users' to 'Prompt for credentials on the secure desktop'" -ExpectedValue 1

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
Check-NetworkSecuritySettings -Description "Check network security settings"

# Device Installation Settings
Check-DeviceInstallationSettings -Description "Check device installation settings"

# Removable Storage Access
Check-RemovableStorageAccess -Description "Check removable storage access"

# Network Settings
Check-NetworkSettings -Description "Check network settings"

# PowerShell Settings
Check-PowerShellSettings -Description "Check PowerShell settings"

# SMB Settings
Check-SMBSettings -Description "Check SMB settings"

# Add these lines after your existing checks
Check-NetworkSecuritySettings -Description "Network Security - Digital Signing and NTLM SSP Settings"
Check-DeviceInstallationSettings -Description "Device Installation Policies"
Check-RemovableStorageAccess -Description "Removable Storage Access Restrictions"
Check-NetworkSettings -Description "Network Settings (LLMNR, Remote Assistance, IPv6, NetBIOS)"
Check-PowerShellSettings -Description "PowerShell Security Settings"
Check-SMBSettings -Description "SMB Version 1 Status"

# Additional Security Settings
Check-AdditionalSecuritySettings -Description "Additional Security Settings"

# Add these to your existing checks section
Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name "NoBackgroundPolicy" -ExpectedValue 0 -Description "Group Policy background refresh"

Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableWebPnPDownload" -ExpectedValue 1 -Description "Print driver downloads over HTTP"

Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "SearchOrderConfig" -ExpectedValue 0 -Description "Internet driver search"

Check-RegistrySetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFontProviders" -ExpectedValue 0 -Description "Font Providers"

Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "RestrictDriverInstallationToAdministrators" -ExpectedValue 1 -Description "Printer driver installation restrictions"

Check-RegistrySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Search" -Name "DisableWebSearch" -ExpectedValue 1 -Description "Search Companion updates"

# Calculate compliance percentage
$compliancePercentage = [math]::Round(($passedChecks / $totalChecks) * 100, 2)

# Build the report
$reportHeader = @"
# Windows Security Configuration Check Report
Generated on: $(Get-Date)

## Summary
- Total checks: $totalChecks
- Passed checks: $passedChecks
- Compliance: $compliancePercentage%

## Detailed Results
"@

$detailedResults = foreach ($result in $results) {
    "### $($result.Description)`n" +
    "**Status:** $($result.Status)`n" +
    "**Details:** $($result.Details)`n"
}

$report = $reportHeader + "`n`n" + ($detailedResults -join "`n")

# Save the results
$report | Out-File -FilePath $resultsFile -Encoding utf8

# Clean up temporary files
Remove-Item -Path $auditpolFile -Force -ErrorAction SilentlyContinue

Write-Host "Security check completed. Results saved to: $resultsFile"
Write-Host "Compliance Score: $compliancePercentage% ($passedChecks/$totalChecks checks passed)"
