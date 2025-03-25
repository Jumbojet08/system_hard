# Ensure script runs with admin privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Output "This script must be run as an Administrator."
    exit 1
}
 
# Log file location
$logFile = "C:\Windows\Temp\Disable_Autorun.log"
 
# Registry key for Autorun settings
$autorunRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
 
try {
    # Disable Autorun by setting 'NoDriveTypeAutoRun' to 0xFF (255)
    # This disables Autorun on all drives: USB, CD-ROM, network, etc.
    Set-ItemProperty -Path $autorunRegPath -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord -Force
    Write-Output "$(Get-Date) - Autorun disabled for all external media" | Out-File -Append -FilePath $logFile
} catch {
    Write-Output "$(Get-Date) - Failed to disable Autorun: $_" | Out-File -Append -FilePath $logFile
}
 
Write-Output "Autorun disabling applied. Log saved at $logFile."
 