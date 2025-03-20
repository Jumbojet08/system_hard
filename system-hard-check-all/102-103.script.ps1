# Registry path for Windows Ink Workspace policies
$regPath = "HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace"

# Ensure the registry path exists
if (!(Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }

# Disable Windows Ink Workspace (0 = Disabled, 1 = Enabled, 2 = Pen Only)
Set-ItemProperty -Path $regPath -Name "AllowWindowsInkWorkspace" -Value 0 -Type DWord -Force

# Disable Suggested Apps in Windows Ink Workspace (0 = Disabled, 1 = Enabled)
Set-ItemProperty -Path $regPath -Name "AllowSuggestedAppsInWindowsInkWorkspace" -Value 0 -Type DWord -Force

Write-Output "Windows Ink Workspace and suggested apps have been disabled."
