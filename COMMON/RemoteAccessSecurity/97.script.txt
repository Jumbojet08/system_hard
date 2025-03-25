# Define the registry path
$RegPath = "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services"

# Check if the registry path exists, if not, create it
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# Set the fDisablePNPRedir registry key to 1 (Enables the policy)
Set-ItemProperty -Path $RegPath -Name "fDisablePNPRedir" -Value 1 -Type DWord

Write-Host "Plug and Play device redirection has been disabled. Restart your computer for changes to take effect." -ForegroundColor Green
