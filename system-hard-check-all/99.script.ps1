# Registry path for User Profile Service settings
$regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"

# Ensure the registry path exists
if (!(Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }

# Set "KeepTempFiles" to 0 (Disabled - Temp folders will be deleted upon exit)
Set-ItemProperty -Path $regPath -Name "KeepTempFiles" -Value 0 -Type DWord -Force

Write-Output "Disabled 'Do not delete temp folders upon exit'."
