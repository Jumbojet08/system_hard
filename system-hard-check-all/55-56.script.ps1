# Registry base path for Software Restriction Policies (SRP)
$srpBasePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"
$srpPaths = "$srpBasePath\262144\Paths"

# Ensure the registry base path exists
if (!(Test-Path $srpBasePath)) { New-Item -Path $srpBasePath -Force | Out-Null }
if (!(Test-Path "$srpBasePath\262144")) { New-Item -Path "$srpBasePath\262144" -Force | Out-Null }
if (!(Test-Path $srpPaths)) { New-Item -Path $srpPaths -Force | Out-Null }

# Define paths to block
$removableDrives = @("D:\*", "E:\*")

# Ensure subkeys for each drive exist and apply SRP rules
for ($i = 0; $i -lt $removableDrives.Count; $i++) {
    $drivePath = "$srpPaths\$i"

    if (!(Test-Path $drivePath)) {
        New-Item -Path $drivePath -Force | Out-Null  # Create subkey if missing
    }

    # Set restriction properties
    Set-ItemProperty -Path $drivePath -Name "ItemData" -Value $removableDrives[$i] -Type String
    Set-ItemProperty -Path $drivePath -Name "SaferFlags" -Value 0x0 -Type DWord
}

# Apply changes
gpupdate /force

Write-Host "Execution from removable disks blocked successfully." -ForegroundColor Green
