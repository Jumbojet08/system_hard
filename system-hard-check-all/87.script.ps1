# Registry path for device authentication using certificate
$RegPath = "HKLM:\Software\Policies\Microsoft\Windows\DeviceCertificate"

# Ensure registry path exists
if (!(Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }

# Set policy to enable automatic device authentication using certificates
Set-ItemProperty -Path $RegPath -Name "EnableDeviceAuthentication" -Value 1 -Type DWord -Force

Write-Host "Device authentication using certificate is now set to Automatic." -ForegroundColor Green
