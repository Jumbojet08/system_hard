# Get all network adapters that are disconnected
$disconnectedAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Disconnected" }

# Disable each disconnected adapter
foreach ($adapter in $disconnectedAdapters) {
    Write-Host "Disabling adapter: $($adapter.Name) ($($adapter.InterfaceDescription))" -ForegroundColor Yellow
    Disable-NetAdapter -Name $adapter.Name -Confirm:$false
}

# Show result
if ($disconnectedAdapters.Count -eq 0) {
    Write-Host "No disconnected adapters found." -ForegroundColor Green
} else {
    Write-Host "All disconnected adapters have been disabled." -ForegroundColor Green
}
