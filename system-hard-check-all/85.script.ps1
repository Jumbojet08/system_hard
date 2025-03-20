# Registry path for disabling Windows CEIP
$RegPath = "HKLM:\Software\Policies\Microsoft\SQMClient\Windows"

# Ensure registry path exists
if (!(Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }

# Set the policy to disable CEIP
Set-ItemProperty -Path $RegPath -Name "CEIPEnable" -Value 0 -Type DWord -Force

Write-Host "Windows Customer Experience Improvement Program is now turned off." -ForegroundColor Green
