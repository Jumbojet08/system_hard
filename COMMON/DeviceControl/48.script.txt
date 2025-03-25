# Registry path for device installation restriction policies
$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"

# Ensure the registry path exists
if (!(Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# Enable custom title display
Set-ItemProperty -Path $RegPath -Name "DisplayCustomMessageWhenPrevented" -Value 1 -Type DWord

# Set the custom title (modify as needed)
$CustomTitle = "Device Installation Blocked"
Set-ItemProperty -Path $RegPath -Name "CustomTitle" -Value $CustomTitle -Type String

Write-Output "Custom title for blocked device installation has been set."
