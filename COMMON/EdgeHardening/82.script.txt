# Registry path for disabling the "Order Prints" picture task
$RegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"

# Ensure registry path exists
if (!(Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }

# Set the policy to disable the "Order Prints" feature
Set-ItemProperty -Path $RegPath -Name "NoOnlinePrintsWizard" -Value 1 -Type DWord -Force

Write-Host "Turn off the 'Order Prints' picture task is now enabled." -ForegroundColor Green
