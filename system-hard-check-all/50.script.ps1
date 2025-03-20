# Registry path for Software Restriction Policies
$srpPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Paths"

# Ensure the registry path exists
if (!(Test-Path $srpPath)) {
    New-Item -Path $srpPath -Force | Out-Null
}

# Block execution from removable drives (e.g., D:\, E:\)
Set-ItemProperty -Path "$srpPath\0" -Name "ItemData" -Value "D:\*" -Type String
Set-ItemProperty -Path "$srpPath\1" -Name "ItemData" -Value "E:\*" -Type String
Set-ItemProperty -Path "$srpPath\0" -Name "SaferFlags" -Value 0x0 -Type DWord
Set-ItemProperty -Path "$srpPath\1" -Name "SaferFlags" -Value 0x0 -Type DWord

# Apply changes
gpupdate /force

Write-Output "Execution from removable disks blocked successfully."
