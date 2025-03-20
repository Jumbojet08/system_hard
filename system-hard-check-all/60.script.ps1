# Disable SMBv1 Server (Prevents the system from acting as an SMBv1 server)
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# Remove SMBv1 Client (Prevents the system from connecting to SMBv1 shares)
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart

Write-Host "SMBv1 has been disabled. A restart may be required for changes to take effect." -ForegroundColor Green
