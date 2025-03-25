# Registry path for Group Policy background refresh
$RegPath = "HKLM:\Software\Policies\Microsoft\Windows\Group Policy"

# Ensure the registry path exists
if (!(Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }

# Disable "Turn off background refresh of Group Policy" by setting it to 0
Set-ItemProperty -Path $RegPath -Name "DisableBkGndGroupPolicy" -Value 0 -Type DWord -Force

Write-Host "Background refresh of Group Policy is enabled." -ForegroundColor Green
