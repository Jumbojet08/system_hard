# Registry path for UAC settings
$uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

try {
    # Enable "Switch to the secure desktop when prompting for elevation"
    Set-ItemProperty -Path $uacPath -Name "PromptOnSecureDesktop" -Value 1 -Type DWord -Force

    Write-Output "UAC setting 'Switch to the secure desktop when prompting for elevation' is now ENABLED."
    Write-Output "A system restart may be required for changes to take effect."
} catch {
    Write-Output "Failed to apply the setting: $_"
}
