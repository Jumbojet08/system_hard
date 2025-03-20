# Define the registry path
$RegPath = "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services"

# Check if the registry path exists, if not, create it
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# Set the fPromptForPassword registry key to 1 (Enables the policy)
Set-ItemProperty -Path $RegPath -Name "fPromptForPassword" -Value 1 -Type DWord

Write-Host "Clients will now always be prompted for a password upon connection. Restart your computer for changes to take effect." -ForegroundColor Green
