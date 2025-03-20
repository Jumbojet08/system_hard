# Registry path for Web publishing and online ordering wizards policy
$RegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"

# Ensure the registry path exists
if (!(Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }

# Enable "Turn off Internet download for Web publishing and online ordering wizards" by setting the value to 1
Set-ItemProperty -Path $RegPath -Name "NoWebServices" -Value 1 -Type DWord -Force

Write-Host "Internet download for Web publishing and online ordering wizards is now disabled." -ForegroundColor Green
