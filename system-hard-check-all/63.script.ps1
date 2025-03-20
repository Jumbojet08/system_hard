# Registry path for Netlogon security settings
$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"

# Enable strong session key requirement
Set-ItemProperty -Path $RegPath -Name "RequireStrongKey" -Value 1 -Type DWord -Force

Write-Host "Strong session key requirement has been enabled." -ForegroundColor Green
