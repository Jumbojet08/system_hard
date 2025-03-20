# Registry path for insecure guest logons setting
$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"

# Disable insecure guest logons (set to 0)
Set-ItemProperty -Path $RegPath -Name "AllowInsecureGuestAuth" -Value 0 -Type DWord -Force

Write-Host "Insecure guest logons have been disabled." -ForegroundColor Green
