# Define the registry path
$RegPath = "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services"

# Check if the registry path exists, if not, create it
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# Set the fDisableCcm registry key to 1 (Enables the policy)
Set-ItemProperty -Path $RegPath -Name "fDisableCcm" -Value 1 -Type DWord

Write-Host "COM port redirection has been disabled. Restart your computer for changes to take effect." -ForegroundColor Green
