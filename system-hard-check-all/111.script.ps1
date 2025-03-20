# SmartScreen settings path
$regPath = "HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter"

# Ensure registry path exists
if (!(Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }

# Enable SmartScreen and prevent bypassing
Set-ItemProperty -Path $regPath -Name "EnabledV9" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $regPath -Name "PreventOverride" -Value 1 -Type DWord -Force

Write-Output "SmartScreen for Internet Explorer is enabled and centrally managed."
