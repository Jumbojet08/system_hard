# Registry path for Font Providers setting
$RegPath = "HKLM:\Software\Policies\Microsoft\Windows\System"

# Disable Enable Font Providers (set to 0)
Set-ItemProperty -Path $RegPath -Name "EnableFontProviders" -Value 0 -Type DWord -Force

Write-Host "Font Providers have been disabled." -ForegroundColor Green
