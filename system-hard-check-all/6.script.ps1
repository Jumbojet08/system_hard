# Disable CD-ROM by setting 'Start' value to 4 (Disabled)
try {
    Set-ItemProperty -Path $cdromRegPath -Name "Start" -Value 4 -Force
    Write-Output "$(Get-Date) - CD-ROM disabled via registry" | Out-File -Append -FilePath $logFile
} catch {
    Write-Output "$(Get-Date) - Failed to modify registry: $_" | Out-File -Append -FilePath $logFile
}
 
# Disable CD-ROM devices using PnPUtil
try {
    $cdromDevices = Get-PnpDevice | Where-Object { $_.Class -eq "CDROM" }
    foreach ($device in $cdromDevices) {
        Disable-PnpDevice -InstanceId $device.InstanceId -Confirm:$false
        Write-Output "$(Get-Date) - Disabled CD-ROM device: $($device.FriendlyName)" | Out-File -Append -FilePath $logFile
    }
} catch {
    Write-Output "$(Get-Date) - Failed to disable CD-ROM devices: $_" | Out-File -Append -FilePath $logFile
}
 
Write-Output "CD-ROM disabling applied. Log saved at $logFile."
