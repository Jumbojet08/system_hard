# Check if Internet Explorer is installed
$ieStatus = Get-WindowsOptionalFeature -Online -FeatureName "Internet-Explorer-Optional-amd64"

if ($ieStatus.State -eq "Enabled") {
    # Disable Internet Explorer
    Disable-WindowsOptionalFeature -Online -FeatureName "Internet-Explorer-Optional-amd64" -NoRestart -ErrorAction SilentlyContinue
    Write-Output "Internet Explorer has been disabled."
} else {
    Write-Output "Internet Explorer is already disabled."
}
