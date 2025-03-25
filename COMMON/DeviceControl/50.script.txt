# Get removable drives dynamically
$removableDrives = Get-WMIObject Win32_DiskDrive | Where-Object { $_.MediaType -match "Removable Media" } | 
    ForEach-Object { Get-WMIObject Win32_LogicalDisk | Where-Object { $_.DeviceID -match $_.Name } } |
    Select-Object -ExpandProperty DeviceID

# Convert to Software Restriction Policies format (e.g., "E:\*")
$removableDrives = $removableDrives | ForEach-Object { "$_\*" }

# Registry path for Software Restriction Policies
$srpPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Paths"

# Ensure the registry path exists
if (!(Test-Path $srpPath)) {
    New-Item -Path $srpPath -Force | Out-Null
}

# Apply restrictions to each removable drive
for ($i = 0; $i -lt $removableDrives.Count; $i++) {
    $drivePath = "$srpPath\$i"
    
    # Ensure numbered path exists
    if (!(Test-Path $drivePath)) {
        New-Item -Path $drivePath -Force | Out-Null
    }

    # Set restriction properties
    Set-ItemProperty -Path $drivePath -Name "ItemData" -Value $removableDrives[$i] -Type String
    Set-ItemProperty -Path $drivePath -Name "SaferFlags" -Value 0x0 -Type DWord
}

# Apply changes
gpupdate /force

Write-Output "Execution from removable disks blocked successfully."
