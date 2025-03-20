# Define the registry path
$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

# Check if the registry path exists, if not, create it
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# Set NoConnectedUser to 0 (Allows Microsoft accounts to be optional)
Set-ItemProperty -Path $RegPath -Name "NoConnectedUser" -Value 0 -Type DWord

Write-Host "Microsoft account restriction disabled. Restart your computer for changes to take effect." -ForegroundColor Green
