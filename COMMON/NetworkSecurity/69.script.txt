# Registry path for LLTDIO (Link-Layer Topology Discovery Mapper I/O Driver)
$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\lltdio"

# Disable LLTDIO by setting 'Start' value to 4 (Disabled)
Set-ItemProperty -Path $RegPath -Name "Start" -Value 4 -Type DWord -Force

Write-Host "Mapper I/O (LLTDIO) driver has been disabled." -ForegroundColor Green
