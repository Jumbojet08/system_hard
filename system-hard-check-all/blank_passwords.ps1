# Enable "Limit local account use of blank passwords to console logon only"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1 -Force

# Confirm the change
$Status = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse"
if ($Status.LimitBlankPasswordUse -eq 1) {
    Write-Host "Blank password restriction enabled successfully!" -ForegroundColor Green
} else {
    Write-Host "Failed to enable blank password restriction." -ForegroundColor Red
}
