# Define Login Banner Title and Message
$logonTitle = "Warning!"
$logonMessage = "Unauthorized access is prohibited. Your actions may be monitored."

# Registry paths for login banner
$logonTitlePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$logonMessagePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

# Set Login Banner Title
Set-ItemProperty -Path $logonTitlePath -Name "LegalNoticeCaption" -Value $logonTitle

# Set Login Banner Message
Set-ItemProperty -Path $logonMessagePath -Name "LegalNoticeText" -Value $logonMessage

Write-Output "Login banner has been configured."
