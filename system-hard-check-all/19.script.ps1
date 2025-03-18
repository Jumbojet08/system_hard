# Registry path for Admin Approval Mode setting
$uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

try {
    # Enable Admin Approval Mode for the built-in Administrator account
    Set-ItemProperty -Path $uacPath -Name "FilterAdministratorToken" -Value 1 -Type DWord -Force

    Write-Output "Admin Approval Mode for the built-in Administrator account has been enabled."
    Write-Output "A system restart is required for changes to take effect."
} catch {
    Write-Output "Failed to enable Admin Approval Mode: $_"
}
