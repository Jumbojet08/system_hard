# Registry path for UAC settings
$uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

try {
    # Enable "Only elevate UIAccess applications that are installed in secure locations"
    Set-ItemProperty -Path $uacPath -Name "EnableSecureUIAPaths" -Value 1 -Type DWord -Force

    Write-Output "UAC setting 'Only elevate UIAccess applications installed in secure locations' is now ENABLED."
    Write-Output "A system restart may be required for changes to take effect."
} catch {
    Write-Output "Failed to apply the setting: $_"
}
