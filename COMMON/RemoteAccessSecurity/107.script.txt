# Registry path for RDS session timeout settings
$regPath = "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services"

# Ensure the registry path exists
if (!(Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set time limit for idle RDP sessions (15 minutes = 900 seconds)
Set-ItemProperty -Path $regPath -Name "MaxIdleTime" -Value 900 -Type DWord -Force

Write-Output "Time limit for idle Remote Desktop sessions set to 15 minutes."
