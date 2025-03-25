# Registry path for secure logon settings
$logonPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

try {
    # Set "Do not require CTRL+ALT+DEL" to Disabled (0) to enforce secure logon
    Set-ItemProperty -Path $logonPath -Name "DisableCAD" -Value 0 -Type DWord -Force

    Write-Output "Secure logon requirement (CTRL+ALT+DEL) is now ENABLED."
    Write-Output "A system restart may be required for changes to take effect."
} catch {
    Write-Output "Failed to apply the setting: $_"
}
