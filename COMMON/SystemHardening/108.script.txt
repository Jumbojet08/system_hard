# Define Recycle Bin cleanup task name
$taskName = "Auto-Clear Recycle Bin"

# Create a scheduled task to delete files older than 7 days
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -Command `"Get-ChildItem 'C:\$Recycle.Bin' -Recurse | Where-Object {($_.LastWriteTime -lt (Get-Date).AddDays(-7))} | Remove-Item -Force -Recurse`""

$trigger = New-ScheduledTaskTrigger -Daily -At 12:00PM
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Description "Automatically deletes Recycle Bin files older than 7 days"
Write-Output "Scheduled task '$taskName' created to delete files older than 7 days."
