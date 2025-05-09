# Registry path for Multicast Name Resolution setting
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
$logFile = "C:\Logs\SecurityConfig.log"

# Ensure the registry path exists
if (!(Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Disable Multicast Name Resolution (LLMNR)
try {
    Set-ItemProperty -Path $regPath -Name "EnableMulticast" -Value 0 -Type DWord -Force
    Write-Host "Multicast Name Resolution (LLMNR) disabled successfully." -ForegroundColor Green
    "$(Get-Date) - Multicast Name Resolution (LLMNR) disabled successfully." | Out-File -Append -FilePath $logFile
} catch {
    Write-Host "Failed to disable LLMNR: $_" -ForegroundColor Red
    "$(Get-Date) - Failed to disable LLMNR: $_" | Out-File -Append -FilePath $logFile
}

# Force Group Policy update to apply changes
gpupdate /force 
Write-Host "Multicast Name Resolution settings applied."
