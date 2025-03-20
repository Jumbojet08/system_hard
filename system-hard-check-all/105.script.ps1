# Registry path for Remote Desktop drive redirection
$regPath = "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services"

# Check if fDisableCdm exists and is set to 1 (which means drive redirection is disabled)
if (Test-Path $regPath) {
    $value = Get-ItemProperty -Path $regPath -Name "fDisableCdm" -ErrorAction SilentlyContinue
    if ($value.fDisableCdm -eq 1) {
        Write-Output "Drive redirection is disabled."
    } else {
        Write-Output "Drive redirection is enabled or not configured."
    }
} else {
    Write-Output "Remote Desktop policy settings not found. Drive redirection may be enabled by default."
}
