# Registry path for Device Installation policies
$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"

# Ensure the registry path exists
if (!(Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# Enable "Allow Administrators to Override Device Installation Restriction"
Set-ItemProperty -Path $RegPath -Name "AllowAdminInstall" -Value 1 -Type DWord

Write-Output "Administrators can now override device installation restrictions."
