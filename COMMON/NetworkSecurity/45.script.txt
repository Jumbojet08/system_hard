# Set Minimum Session Security for NTLM SSP Based Clients
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinClientSec" -Value 0x20080030

Write-Output "Minimum session security for NTLM SSP-based clients is configured."
