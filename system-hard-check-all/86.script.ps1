# Registry path for disabling Windows Error Reporting
$RegPath = "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting"

# Ensure registry path exists
if (!(Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }

# Set the policy to disable Windows Error Reporting
Set-ItemProperty -Path $RegPath -Name "Disabled" -Value 1 -Type DWord -Force

Write-Host "Windows Error Reporting is now turned off." -ForegroundColor Green
