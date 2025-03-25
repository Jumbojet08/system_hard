# Ensure Windows Time service is set to start automatically
Set-Service -Name w32time -StartupType Automatic

# Set NTP Server
$NtpServer = "time.windows.com,0x9"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -Name "NtpServer" -Value $NtpServer -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -Name "Type" -Value "NTP" -Force

# Enable NTP Client
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config" -Name "Enabled" -Value 1 -Force

# Restart Windows Time service
Restart-Service w32time -Force

# Force NTP sync
w32tm /config /update
w32tm /resync

Write-Output "Windows NTP Client enabled and synced with $NtpServer"
