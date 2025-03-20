# Registry path for device installation restriction policies
$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"

# Ensure the registry path exists
if (!(Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# Enable custom message display
Set-ItemProperty -Path $RegPath -Name "DisplayCustomMessageWhenPrevented" -Value 1 -Type DWord

# Set the custom message (modify the message as needed)
$CustomMessage = "Device installation is restricted by your system administrator. Contact IT support for assistance."
Set-ItemProperty -Path $RegPath -Name "CustomMessage" -Value $CustomMessage -Type String

Write-Output "Custom message for blocked device installation has been set."
