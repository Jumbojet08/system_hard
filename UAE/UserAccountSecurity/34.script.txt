$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$RegName = "Security\Recovery Console\SetCommandLogon"

try {
    # Disable automatic administrative logon for Recovery Console
    Set-ItemProperty -Path $RegPath -Name "RecoveryConsole_AutoAdminLogon" -Value 0 -Type DWord -Force
    
    Write-Output "Successfully disabled 'Recovery Console: Allow automatic administrative logon'."
} catch {
    Write-Output "Error: $_"
}
