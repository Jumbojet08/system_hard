# Registry path for RDP client settings
$regPath = "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services"

# Ensure the path exists
if (!(Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Enable "Do not allow passwords to be saved" (Set to 1)
Set-ItemProperty -Path $regPath -Name "DisablePasswordSaving" -Value 1 -Type DWord -Force

Write-Output "Password saving in Remote Desktop Connection client is now disabled."
