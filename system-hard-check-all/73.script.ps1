# Registry path for Internet Connection Wizard policy
$RegPath = "HKLM:\Software\Policies\Microsoft\Internet Connection Wizard"

# Ensure the registry path exists
if (!(Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }

# Enable "Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com" by setting it to 1
Set-ItemProperty -Path $RegPath -Name "ExitOnMSICW" -Value 1 -Type DWord -Force

Write-Host "Internet Connection Wizard is disabled when referring to Microsoft.com." -ForegroundColor Green
