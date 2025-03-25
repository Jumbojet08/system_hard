# Registry path for disabling registration to Microsoft.com
$RegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"

# Ensure registry path exists
if (!(Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }

# Set the policy to disable registration if URL refers to Microsoft.com
Set-ItemProperty -Path $RegPath -Name "NoRegistration" -Value 1 -Type DWord -Force

Write-Host "Turn off Registration if URL connection is referring to Microsoft.com is now enabled." -ForegroundColor Green
