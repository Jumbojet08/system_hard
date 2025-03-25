# Registry path for disabling Search Companion content file updates
$RegPath = "HKLM:\Software\Policies\Microsoft\SearchCompanion"

# Ensure registry path exists
if (!(Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }

# Set the policy to disable Search Companion content file updates
Set-ItemProperty -Path $RegPath -Name "DisableContentFileUpdates" -Value 1 -Type DWord -Force

Write-Host "Turn off Search Companion content file updates is now enabled." -ForegroundColor Green
