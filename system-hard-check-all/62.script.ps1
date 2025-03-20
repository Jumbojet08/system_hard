# Registry path for secure channel settings
$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"

# Enable secure channel encryption/signing
Set-ItemProperty -Path $RegPath -Name "RequireSignOrSeal" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $RegPath -Name "SealSecureChannel" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $RegPath -Name "SignSecureChannel" -Value 1 -Type DWord -Force

Write-Host "Secure channel encryption/signing has been enabled." -ForegroundColor Green
