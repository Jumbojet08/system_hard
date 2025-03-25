
[CmdletBinding()]
param (
    [Parameter(Mandatory=$false, HelpMessage="Specify the path to store the registry backups. Default: D:\RegistryBackups")]
    [string]$BackupPath = "D:\RegistryBackups",

    [Parameter(Mandatory=$false, HelpMessage="Specify the path for the log file. Default: D:\RegistryBackups\RegistryBackup.log")]
    [string]$LogFilePath = "D:\RegistryBackups\RegistryBackup.log"
)

#region Helper Functions

function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [ValidateSet("Info", "Warning", "Error")]
        [string]$Severity = "Info"
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "$Timestamp [$Severity]: $Message"

    try {
        Add-Content -Path $LogFilePath -Value $LogEntry -ErrorAction Stop
    }
    catch {
        Write-Host "Error writing to log file: $($_.Exception.Message)" -ForegroundColor Red
    }

    switch ($Severity) {
        "Error"   { Write-Host $LogEntry -ForegroundColor Red }
        "Warning" { Write-Host $LogEntry -ForegroundColor Yellow }
        Default   { Write-Host $LogEntry }
    }
}

#endregion

#region Main Script

try {
    # Create the backup directory if it doesn't exist
    if (!(Test-Path -Path $BackupPath -PathType Container)) {
        Write-Log "Creating backup directory: $BackupPath"
        New-Item -Path $BackupPath -ItemType Directory -Force -ErrorAction Stop
    }

    # Define the registry hives to backup
    $RegistryHives = @(
        "HKLM" # HKEY_LOCAL_MACHINE
        "HKCU" # HKEY_CURRENT_USER
        "HKCR" # HKEY_CLASSES_ROOT
        "HKU"  # HKEY_USERS
        "HKCC" # HKEY_CURRENT_CONFIG
    )

    Write-Log "Starting registry backup to: $BackupPath"

    # Loop through each registry hive
    foreach ($Hive in $RegistryHives) {
        $BackupFile = Join-Path -Path $BackupPath -ChildPath "$($Hive).reg"
        Write-Log "Backing up hive: $Hive to file: $BackupFile"

        try {
            # Export the registry hive using reg.exe
            & reg.exe export "$Hive" "$BackupFile" /y | Out-Null  # Suppress reg.exe output

            if ($LASTEXITCODE -eq 0) {
                Write-Log "Successfully backed up hive: $Hive"
            } else {
                Write-Log "Failed to backup hive: $Hive.  Reg.exe Exit Code: $($LASTEXITCODE)" -Severity Error
            }
        }
        catch {
            Write-Log "Error backing up hive: $Hive - $($_.Exception.Message)" -Severity Error
        }
    }

    Write-Log "Registry backup completed successfully."

}
catch {
    Write-Log "An unexpected error occurred: $($_.Exception.Message)" -Severity Error
    Write-Log "Script execution stopped." -Severity Error
    exit 1 # Indicate failure
}

#endregion