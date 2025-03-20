# Registry path for Point and Print Restrictions
$RegPath = "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"

# Ensure the registry path exists
if (!(Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }

# Enable Point and Print Restrictions
Set-ItemProperty -Path $RegPath -Name "NoWarningNoElevationOnInstall" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $RegPath -Name "NoWarningNoElevationOnUpdate" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $RegPath -Name "UpdatePromptSettings" -Value 0 -Type DWord -Force

Write-Host "Point and Print Restrictions enabled for installing and updating printer drivers." -ForegroundColor Green
