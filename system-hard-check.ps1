# Uninstall specific AppxPackages for all users
$appsToRemove = @(
    "*solitaire*",
    "*gaming*",
    "*linkedin*",
    "*spotify*",
    "*windowsstore*",
    "*MicrosoftFamily*",
    "*windowsmaps*",
    "*zunemusic*",
    "*zunevideo*",
    "*teams*",
    "*bingnews*",
    "*bingweather*",
    "*windowscommunicationsapps*",
    "*Outlook*"
)
 
foreach ($app in $appsToRemove) {
    Get-AppxPackage -AllUsers $app | Remove-AppxPackage -ErrorAction SilentlyContinue
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -like $app } | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
}
 
# Uninstall OneDrive
Write-Host "Uninstalling OneDrive..."
Start-Process "$env:SystemRoot\System32\OneDriveSetup.exe" -ArgumentList "/uninstall" -NoNewWindow -Wait
 
# Disable Windows Media Player (Feature Removal)
Write-Host "Disabling Windows Media Player..."
Disable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart -ErrorAction SilentlyContinue
 
# Disable Microsoft Store (Group Policy Registry)
Write-Host "Disabling Microsoft Store..."
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore" /v RemoveWindowsStore /t REG_DWORD /d 1 /f
 
# Remove InboxGames
Write-Host "Removing InboxGames..."
Get-WindowsCapability -Online | Where-Object Name -like "InboxGames*" | Remove-WindowsCapability -Online
 
# Remove MSN Explorer
Write-Host "Removing MSN Explorer..."
Get-WindowsCapability -Online | Where-Object Name -like "MSNExplorer*" | Remove-WindowsCapability -Online
 
# Remove Messaging App (MSMessages)
Write-Host "Removing Messaging App..."
Get-WindowsCapability -Online | Where-Object Name -like "MSMessages*" | Remove-WindowsCapability -Online
 
# Remove Outlook Express (if applicable)
Write-Host "Removing Outlook Express..."
Get-WindowsCapability -Online | Where-Object Name -like "OutlookExpress*" | Remove-WindowsCapability -Online
 
Write-Host "All specified applications have been removed (if applicable). Restart may be required."