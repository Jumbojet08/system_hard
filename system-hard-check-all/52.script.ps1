# Registry path for Multicast Name Resolution setting
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"

# Ensure the registry path exists
if (!(Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Disable Multicast Name Resolution (LLMNR)
try {
    Set-ItemProperty -Path $regPath -Name "EnableMulticast" -Value 0 -Type DWord -Force
    Write-Output "$(Get-Date) - Multicast Name Resolution (LLMNR) disabled successfully." | Out-File -Append -FilePath $logFile
} catch {
    Write-Output "$(Get-Date) - Failed to disable LLMNR: $_" | Out-File -Append -FilePath $logFile
}

# Force Group Policy update to apply changes
gpupdate /force 
Write-Output "Multicast Name Resolution has been disabled."