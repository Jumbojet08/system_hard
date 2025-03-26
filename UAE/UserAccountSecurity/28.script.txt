# Registry path for LAN Manager hash storage setting
$lmPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

try {
    # Set "NoLMHash" to 0 to allow storing LAN Manager hash values
    Set-ItemProperty -Path $lmPath -Name "NoLMHash" -Value 0 -Type DWord -Force

    Write-Output "LAN Manager hash storage is now allowed."
    Write-Output "A system restart may be required for changes to take effect."
} catch {
    Write-Output "Failed to apply the setting: $_"
}
