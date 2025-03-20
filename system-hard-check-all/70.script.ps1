# Registry path for RSPNDR (Link-Layer Topology Discovery Responder Driver)
$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\RSPNDR"

# Disable RSPNDR by setting 'Start' value to 4 (Disabled)
Set-ItemProperty -Path $RegPath -Name "Start" -Value 4 -Type DWord -Force

Write-Host "Responder (RSPNDR) driver has been disabled." -ForegroundColor Green
