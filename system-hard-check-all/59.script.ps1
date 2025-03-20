# Get all network adapters with IP enabled
$adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }

# Disable NetBIOS over TCP/IP (Set to 2: "Disable NetBIOS")
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(2) | Out-Null
    Write-Host "NetBIOS disabled for adapter: $($adapter.Description)" -ForegroundColor Green
}

Write-Host "NetBIOS over TCP/IP has been disabled for all IP-enabled network adapters."
