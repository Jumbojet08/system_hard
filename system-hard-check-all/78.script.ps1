# Registry path for limiting print driver installation
$RegPath = "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"

# Ensure the registry path exists
if (!(Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }

# Enable 'Limit print driver installation to Administrators'
Set-ItemProperty -Path $RegPath -Name "RestrictDriverInstallationToAdministrators" -Value 1 -Type DWord -Force

Write-Host "Print driver installation is now restricted to Administrators only." -ForegroundColor Green
