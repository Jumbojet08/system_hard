Configure Administrator level accounts for all necessary admins in accordance with the Access Control Framework
 
# Ensure script runs with admin privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Output "This script must be run as an Administrator."
    exit 1
}
 
# Log file location
$logFile = "C:\Windows\Temp\LocalUsers_List.log"
 
# List all local users and save to log file
Write-Output "Listing all local users on $(Get-Date):" | Out-File -FilePath $logFile
Get-LocalUser | Select-Object Name, Enabled, Description | Format-Table -AutoSize | Out-File -Append -FilePath $logFile
 
# Display output in console
Get-LocalUser | Select-Object Name, Enabled, Description | Format-Table -AutoSize
Write-Output "Local user list saved at $logFile."