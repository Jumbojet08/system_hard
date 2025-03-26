# Registry path for interactive logon message settings
$logonPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

# Define the logon message text
$logonMessage = @"
WARNING: Unauthorized access to this system is prohibited.
By proceeding, you acknowledge that your activities may be monitored.
Unauthorized use may result in disciplinary action or legal consequences.
"@

try {
    # Configure logon message text
    Set-ItemProperty -Path $logonPath -Name "LegalNoticeText" -Value $logonMessage -Type String -Force

    Write-Output "Interactive logon message has been configured successfully."
    Write-Output "A system restart may be required for changes to take effect."
} catch {
    Write-Output "Failed to apply the setting: $_"
}
