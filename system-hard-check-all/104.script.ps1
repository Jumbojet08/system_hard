# Registry path for Windows Media Player codec download prevention
$regPath = "HKLM:\Software\Policies\Microsoft\WindowsMediaPlayer"

# Ensure the registry path exists
if (!(Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }

# Enable Prevent Codec Download (1 = Enabled, 0 = Disabled)
Set-ItemProperty -Path $regPath -Name "PreventCodecDownload" -Value 1 -Type DWord -Force

Write-Output "Prevent Codec Download policy has been enabled."
