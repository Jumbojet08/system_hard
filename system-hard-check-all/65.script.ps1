# Registry path for UAC settings
$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

# Deny elevation prompt for standard users (set to 0)
Set-ItemProperty -Path $RegPath -Name "ConsentPromptBehaviorUser" -Value 0 -Type DWord -Force

Write-Host "Elevation prompt for standard users has been denied." -ForegroundColor Green
