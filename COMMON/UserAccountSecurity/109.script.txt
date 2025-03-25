# Registry path for UAC setting
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI"

# Ensure the registry path exists
if (!(Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the value to disable account enumeration on elevation
Set-ItemProperty -Path $regPath -Name "EnumerateAdministrators" -Value 0 -Type DWord -Force

Write-Output "Enumerate administrator accounts on elevation is now disabled."
