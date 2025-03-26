$SecPolFile = "C:\Windows\Temp\secpol.cfg"

try {
    # Export current security policy
    secedit /export /cfg $SecPolFile

    # Remove "Debug programs" privilege
    (Get-Content $SecPolFile) -replace "SeDebugPrivilege = .*", "SeDebugPrivilege =" | Set-Content $SecPolFile

    # Apply updated security policy
    secedit /configure /db C:\Windows\security\local.sdb /cfg $SecPolFile /areas USER_RIGHTS

    # Cleanup
    Remove-Item $SecPolFile -Force

    Write-Output "Successfully removed 'Debug programs' right from all accounts."
} catch {
    Write-Output "Error: $_"
}
