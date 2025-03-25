# Block Internet Access by Setting a Fake Proxy
$RegPath = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
New-Item -Path $RegPath -Force | Out-Null
Set-ItemProperty -Path $RegPath -Name ProxyEnable -Value 1
Set-ItemProperty -Path $RegPath -Name ProxyServer -Value "127.0.0.1:8080"
Set-ItemProperty -Path $RegPath -Name ProxyOverride -Value "<local>"

# Disable Direct Internet Access via Firewall
New-NetFirewallRule -DisplayName "Block Internet Access" -Direction Outbound -Action Block -RemoteAddress Any -Enabled True

Write-Host "Internet access has been disabled." -ForegroundColor Green
