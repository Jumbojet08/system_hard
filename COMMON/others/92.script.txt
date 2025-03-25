# Registry path for App Sharing Policy
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModelUnlock"

# Ensure the registry path exists
if (!(Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }

# Disable the feature by setting "AllowSharedLocalAppData" to 0
Set-ItemProperty -Path $regPath -Name "AllowSharedLocalAppData" -Value 0 -Type DWord -Force

Write-Output "Disabled 'Allow a Windows app to share application data between users'."
