# Registry path for LAN Manager and NTLM settings
$lmPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

try {
    # Disable the storage of LAN Manager hash values
    Set-ItemProperty -Path $lmPath -Name "NoLMHash" -Value 1 -Type DWord -Force

    # Set LAN Manager authentication level to NTLMv2 only
    # Value 5 = Send NTLMv2 response only. Refuse LM & NTLM
    Set-ItemProperty -Path $lmPath -Name "LmCompatibilityLevel" -Value 5 -Type DWord -Force

    Write-Output "LAN Manager hash storage is disabled, and NTLMv2 authentication is enforced."
    Write-Output "A system restart may be required for changes to take effect."
} catch {
    Write-Output "Failed to apply the setting: $_"
}
