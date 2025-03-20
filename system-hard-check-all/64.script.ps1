# Registry path for shutdown security setting
$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

# Disable shutdown without logging in
Set-ItemProperty -Path $RegPath -Name "ShutdownWithoutLogon" -Value 0 -Type DWord -Force

Write-Host "Shutdown without logging in has been disabled." -ForegroundColor Green
