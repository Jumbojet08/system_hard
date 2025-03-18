# Enable Advanced Security Auditing
$AuditCategories = @(
    "Account Logon", "Account Management", "Logon/Logoff", "Object Access",
    "Policy Change", "Privilege Use", "System", "Detailed Tracking"
)
foreach ($Category in $AuditCategories) { auditpol /set /category:"$Category" /success:enable /failure:enable }

# Configure Event Log Retention & Size
@("Security", "System", "Application") | ForEach-Object {
    wevtutil sl $_ /rt:true
    wevtutil sl $_ /ms:102400  # 100MB log size
}

# Enable PowerShell Logging
$PSLoggingKeys = @(
    "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
    "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription"
)
foreach ($Key in $PSLoggingKeys) { Set-ItemProperty -Path $Key -Name EnableScriptBlockLogging -Value 1 -Force }

# Backup Logs
$logPath = "C:\Logs\AuditLogs"
if (!(Test-Path $logPath)) { New-Item -ItemType Directory -Path $logPath | Out-Null }
@("Security", "System", "Application") | ForEach-Object { wevtutil epl $_ "$logPath\$_-Log.evtx" }

Write-Host "Auditing & logging configured successfully!" -ForegroundColor Green
