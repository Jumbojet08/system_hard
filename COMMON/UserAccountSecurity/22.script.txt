# Registry path for UAC settings
$uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

try {
    # Enable "Detect application installations and prompt for elevation"
    Set-ItemProperty -Path $uacPath -Name "EnableInstallerDetection" -Value 1 -Type DWord -Force

    Write-Output "UAC setting 'Detect application installations and prompt for elevation' is now ENABLED."
    Write-Output "A system restart may be required for changes to take effect."
} catch {
    Write-Output "Failed to apply the setting: $_"
}
