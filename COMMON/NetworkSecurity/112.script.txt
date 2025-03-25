$regPath = "HKLM:\System\CurrentControlSet\Services\FTPSVC\Parameters"

if (Test-Path $regPath) {
    Set-ItemProperty -Path $regPath -Name "AllowAnonymous" -Value 0 -Type DWord -Force
    Write-Output "Anonymous FTP disabled via registry."
} else {
    Write-Output "FTP Service not found."
}
