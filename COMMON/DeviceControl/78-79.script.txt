# Registry path for print driver restrictions
$PointAndPrintRegPath = "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
$SecurityOptionsRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\Policies"

# Ensure registry paths exist
if (!(Test-Path $PointAndPrintRegPath)) { New-Item -Path $PointAndPrintRegPath -Force | Out-Null }
if (!(Test-Path $SecurityOptionsRegPath)) { New-Item -Path $SecurityOptionsRegPath -Force | Out-Null }

# Enable 'Limit print driver installation to Administrators'
Set-ItemProperty -Path $PointAndPrintRegPath -Name "RestrictDriverInstallationToAdministrators" -Value 1 -Type DWord -Force

# Prevent users from installing printer drivers
Set-ItemProperty -Path $SecurityOptionsRegPath -Name "RestrictUserPrinterInstallation" -Value 1 -Type DWord -Force

Write-Host "Print driver installation is now restricted to Administrators only." -ForegroundColor Green
Write-Host "Users are prevented from installing printer drivers." -ForegroundColor Green
