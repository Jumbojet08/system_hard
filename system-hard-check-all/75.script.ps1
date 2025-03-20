# Registry path for disabling HTTP printing
$RegPath = "HKLM:\Software\Policies\Microsoft\Windows NT\Printers"

# Ensure the registry path exists
if (!(Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }

# Enable "Turn off printing over HTTP" by setting the value to 1
Set-ItemProperty -Path $RegPath -Name "DisableHTTPPrinting" -Value 1 -Type DWord -Force

Write-Host "Printing over HTTP has been disabled." -ForegroundColor Green
