# Registry path for restricting anonymous enumeration
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

try {
    # Enable "Do not allow anonymous enumeration of SAM accounts and shares"
    Set-ItemProperty -Path $regPath -Name "RestrictAnonymous" -Value 1 -Type DWord -Force

    Write-Output "Anonymous enumeration of SAM accounts and shares is now restricted."
    Write-Output "A system restart may be required for changes to take effect."
} catch {
    Write-Output "Failed to apply the setting: $_"
}
