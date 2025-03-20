# Registry path for disabling Windows Messenger CEIP
$RegPath = "HKLM:\Software\Policies\Microsoft\Messenger\Client"

# Ensure registry path exists
if (!(Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }

# Set the policy to disable CEIP for Windows Messenger
Set-ItemProperty -Path $RegPath -Name "CEIP" -Value 2 -Type DWord -Force

Write-Host "Windows Messenger Customer Experience Improvement Program is now turned off." -ForegroundColor Green
