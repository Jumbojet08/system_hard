# Registry path for logon message settings
$logonPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

# Set custom message title and text
$logonTitle = "Authorized Access Only"
$logonMessage = "This system is for authorized users only. Unauthorized access is prohibited and may result in legal action."

try {
    # Configure logon message title
    Set-ItemProperty -Path $logonPath -Name "LegalNoticeCaption" -Value $logonTitle -Type String -Force
    
    # Configure logon message text
    Set-ItemProperty -Path $logonPath -Name "LegalNoticeText" -Value $logonMessage -Type String -Force

    Write-Output "Logon message title and warning banner have been configured successfully."
    Write-Output "A system restart may be required for changes to take effect."
} catch {
    Write-Output "Failed to apply the setting: $_"
}
