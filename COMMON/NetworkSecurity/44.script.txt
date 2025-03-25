# Enable Digitally Sign Communication (Always) for Microsoft Network Client
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1

Write-Output "Microsoft Network Client: Digitally Sign Communication (Always) is enabled."
