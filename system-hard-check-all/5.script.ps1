# Registry path for USB storage control
$usbStorageRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR"

# Disable USB storage by setting 'Start' value to 4 (Blocked)
try {
    Set-ItemProperty -Path $usbStorageRegPath -Name "Start" -Value 4 -Force
    Write-Output "$(Get-Date) - USB storage blocked successfully" | Out-File -Append -FilePath $logFile
} catch {
    Write-Output "$(Get-Date) - Failed to block USB storage: $_" | Out-File -Append -FilePath $logFile
}

# Ensure USB input devices (mouse/keyboard) remain enabled
$usbInputDevices = @("HID-compliant mouse", "HID Keyboard Device")

foreach ($device in $usbInputDevices) {
    try {
        Get-PnpDevice | Where-Object { $_.FriendlyName -like "*$device*" } | ForEach-Object {
            Enable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false
            Write-Output "$(Get-Date) - Ensured USB input device is enabled: $device" | Out-File -Append -FilePath $logFile
        }
    } catch {
        Write-Output "$(Get-Date) - Error ensuring input device remains enabled: $_" | Out-File -Append -FilePath $logFile
    }
}

Write-Output "USB storage blocking applied. Log saved at $logFile."
exit 0
