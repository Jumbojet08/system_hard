$SecPolFile = "C:\Windows\Temp\secpol.cfg"

try {
    # Export current security policy
    secedit /export /cfg $SecPolFile

    # Remove "Access this computer from the network" right
    (Get-Content $SecPolFile) -replace "SeNetworkLogonRight = .*", "SeNetworkLogonRight =" | Set-Content $SecPolFile

    # Apply updated security policy
    secedit /configure /db C:\Windows\security\local.sdb /cfg $SecPolFile /areas USER_RIGHTS

    # Cleanup
    Remove-Item $SecPolFile -Force

    Write-Output "Successfully removed 'Access this computer from the network' right from all users."
} catch {
    Write-Output "Error: $_"
}
