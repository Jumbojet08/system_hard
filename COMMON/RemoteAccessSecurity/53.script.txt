# Define registry path and value name
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$regName = "fAllowUnsolicited"

# Ensure the registry path exists
if (!(Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Disable Offer Remote Assistance (0 = Disabled)
Set-ItemProperty -Path $regPath -Name $regName -Value 0 -Type DWord -Force
Write-Host "Offer Remote Assistance has been disabled."
