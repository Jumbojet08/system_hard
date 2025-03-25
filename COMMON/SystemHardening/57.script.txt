# Define the registry path for PowerShell security settings
$RegPath = "HKLM:\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell"

# Ensure the registry path exists
if (!(Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }

# Set PSLockdownPolicy to 4 (Restricted Mode)
Set-ItemProperty -Path $RegPath -Name "PSLockdownPolicy" -Value 4 -Type DWord -Force

Write-Host "PSLockdownPolicy set to Restricted (4)." -ForegroundColor Green
