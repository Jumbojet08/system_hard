# Registry path for Secure RPC Communication
$regPath = "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc"

# Ensure the registry path exists
if (!(Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }

# Enable secure RPC communication by setting "EnableAuthEpResolution" to 1
Set-ItemProperty -Path $regPath -Name "EnableAuthEpResolution" -Value 1 -Type DWord -Force

Write-Output "Enabled 'Require secure RPC communication'."
