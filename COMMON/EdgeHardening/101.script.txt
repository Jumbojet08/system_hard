# Registry path for Windows Defender MAPS settings
$regPath = "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet"

# Ensure the registry path exists
if (!(Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }

# Disable Microsoft MAPS by setting "SpynetReporting" to 0 (Disabled)
Set-ItemProperty -Path $regPath -Name "SpynetReporting" -Value 0 -Type DWord -Force

# Ensure MAPS is completely disabled
Set-ItemProperty -Path $regPath -Name "SubmitSamplesConsent" -Value 2 -Type DWord -Force

Write-Output "Disabled Microsoft MAPS (Windows Defender Cloud-based protection)."
