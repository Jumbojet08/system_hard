# Registry path for print driver download policy
$RegPath = "HKLM:\Software\Policies\Microsoft\Windows NT\Printers"

# Ensure the registry path exists
if (!(Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }

# Enable "Turn off downloading of print drivers over HTTP" by setting it to 1
Set-ItemProperty -Path $RegPath -Name "DisableWebPnPDownload" -Value 1 -Type DWord -Force

Write-Host "Downloading of print drivers over HTTP is disabled." -ForegroundColor Green
