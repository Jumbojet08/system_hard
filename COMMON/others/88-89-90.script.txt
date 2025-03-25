# Registry paths for policies
$LockScreenRegPath = "HKLM:\Software\Policies\Microsoft\Windows\System"
$PinSignInRegPath = "HKLM:\Software\Policies\Microsoft\Windows\System"

# Ensure registry paths exist
if (!(Test-Path $LockScreenRegPath)) { New-Item -Path $LockScreenRegPath -Force | Out-Null }

# Turn off app notifications on the lock screen (Enable)
Set-ItemProperty -Path $LockScreenRegPath -Name "DisableLockScreenAppNotifications" -Value 1 -Type DWord -Force

# Turn off picture password sign-in (Enable)
Set-ItemProperty -Path $LockScreenRegPath -Name "BlockPicturePassword" -Value 1 -Type DWord -Force

# Turn off convenience PIN sign-in (Disable)
Set-ItemProperty -Path $PinSignInRegPath -Name "AllowDomainPINLogon" -Value 0 -Type DWord -Force

Write-Host "Lock screen and sign-in policies configured successfully." -ForegroundColor Green
