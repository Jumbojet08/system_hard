# Registry path for UAC settings
$uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

try {
    # Enable "Virtualize file and registry write failures to per-user locations"
    Set-ItemProperty -Path $uacPath -Name "EnableVirtualization" -Value 1 -Type DWord -Force

    Write-Output "UAC setting 'Virtualize file and registry write failures to per-user locations' is now ENABLED."
    Write-Output "A system restart may be required for changes to take effect."
} catch {
    Write-Output "Failed to apply the setting: $_"
}
