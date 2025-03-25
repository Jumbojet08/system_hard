# Ensure Microsoft Defender Antivirus service is running
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableBehaviorMonitoring $false
Set-MpPreference -DisableBlockAtFirstSeen $false
Set-MpPreference -DisableIOAVProtection $false
Set-MpPreference -DisablePrivacyMode $false
Set-MpPreference -DisableIntrusionPreventionSystem $false

# Enable Cloud Protection
Set-MpPreference -MAPSReporting 2
Set-MpPreference -SubmitSamplesConsent 1

# Ensure Microsoft Defender is set as the active antivirus (Windows 10/11)
Set-MpPreference -UILockdown $false

# Enable scanning for archive files and removable drives
Set-MpPreference -DisableArchiveScanning $false
Set-MpPreference -DisableRemovableDriveScanning $false

# Enable Defender periodic scanning (if another AV is installed)
Set-MpPreference -PassiveMode $false

# Update Defender definitions
Update-MpSignature



Write-Host "Microsoft Defender has been enabled and configured successfully!" -ForegroundColor Green
