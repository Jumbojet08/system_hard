# Registry path for disabling the "Publish to Web" task
$RegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"

# Ensure registry path exists
if (!(Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }

# Set the policy to disable the "Publish to Web" feature
Set-ItemProperty -Path $RegPath -Name "NoPublishingWizard" -Value 1 -Type DWord -Force

Write-Host "Turn off the 'Publish to Web' task for files and folders is now enabled." -ForegroundColor Green
