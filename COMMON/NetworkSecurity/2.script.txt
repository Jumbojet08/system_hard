# Ensure script runs with admin privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Output "This script must be run as an Administrator."
    exit 1
}

# List of unnecessary services to disable
$services = @(
    "DPS", "DiagTrack", "dmwappushservice", "MapsBroker", "iphlpsvc", "PolicyAgent",
    "CscService", "PcaSvc", "RemoteRegistry", "seclogon", "ShellHWDetection",
    "WerSvc", "WpnService", "BTAGService", "BluetoothUserService", "bthserv",
    "QWAVE", "FrameServer", "RMSvc", "DoSvc", "Fax", "WebClient", "IrMon",
    "XboxGipSvc", "XboxNetApiSvc", "XboxVC", "XblAuthManager", "XblGameSave"
)

# Log file location
$logFile = "C:\Windows\Temp\Disable_Services.log"

# Ensure log directory exists
if (!(Test-Path "C:\Windows\Temp")) { New-Item -Path "C:\Windows\Temp" -ItemType Directory -Force }

# Function to disable a service
function Disable-Service {
    param ([string]$serviceName)

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -ne 'Stopped') {
            Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        }
        Set-Service -Name $serviceName -StartupType Disabled
        Write-Output "$(Get-Date) - Disabled service: $serviceName" | Out-File -Append -FilePath $logFile
    } else {
        Write-Output "$(Get-Date) - Service not found: $serviceName" | Out-File -Append -FilePath $logFile
    }
}

# Disable each service in the list
foreach ($service in $services) {
    Disable-Service -serviceName $service
}

Write-Output "All unnecessary services have been disabled. Log saved at $logFile."
exit 0
