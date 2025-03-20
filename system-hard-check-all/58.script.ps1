# Disable IPv6 for all network adapters
Get-NetAdapterBinding -ComponentID ms_tcpip6 | ForEach-Object {
    Disable-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip6 -Confirm:$false
}

Write-Host "IPv6 has been disabled for all network adapters." -ForegroundColor Green
