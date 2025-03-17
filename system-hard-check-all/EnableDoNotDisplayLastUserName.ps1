# Ensure script runs with admin privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Output "This script must be run as an Administrator."
    exit 1
}
 
# Log file location
$logFile = "C:\Windows\Temp\Disable_LastUsername.log"
 
# Registry path for Interactive Logon setting
$logonRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
 
try {
    # Enable "Do not display last user name" by setting "DontDisplayLastUserName" to 1
    Set-ItemProperty -Path $logonRegPath -Name "DontDisplayLastUserName" -Value 1 -Type DWord -Force
    Write-Output "$(Get-Date) - Enabled 'Do not display last user name' in Interactive Logon settings" | Out-File -Append -FilePath $logFile
} catch {
    Write-Output "$(Get-Date) - Failed to apply the setting: $_" | Out-File -Append -FilePath $logFile
}
 
Write-Output "Setting applied. Log saved at $logFile."
exit 0