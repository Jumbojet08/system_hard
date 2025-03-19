# Set NTP Server
$NtpServer = "time.windows.com,0x9"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -Name "NtpServer" -Value $NtpServer
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -Name "Type" -Value "NTP"

# Enable NTP Client and Force Sync
Restart-Service w32time -Force
w32tm /resync

Write-Output "NTP configured and synced with $NtpServer"
