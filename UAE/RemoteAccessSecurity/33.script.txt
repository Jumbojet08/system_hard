$SecPolFile = "C:\Windows\Temp\secpol.cfg"

try {
    # Export current security policy
    secedit /export /cfg $SecPolFile

    # Define allowed users/groups (Keep only "Administrators" or add specific users)
    $AllowedUsers = "SeRemoteShutdownPrivilege = Administrators"

    # Modify the setting in the security policy file
    (Get-Content $SecPolFile) -replace "SeRemoteShutdownPrivilege = .*", $AllowedUsers | Set-Content $SecPolFile

    # Apply updated security policy
    secedit /configure /db C:\Windows\security\local.sdb /cfg $SecPolFile /areas USER_RIGHTS

    # Cleanup
    Remove-Item $SecPolFile -Force

    Write-Output "Successfully restricted 'Force shutdown from a remote system' privilege to Administrators."
} catch {
    Write-Output "Error: $_"
}
