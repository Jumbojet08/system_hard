# Registry path for User Profile Service settings
$regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"

# Ensure the registry path exists
if (!(Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }

# Set "UseTempFoldersPerSession" to 1 (Enabled)
Set-ItemProperty -Path $regPath -Name "UseTempFoldersPerSession" -Value 1 -Type DWord -Force

Write-Output "Enabled 'Do not use temporary folders per session'."
