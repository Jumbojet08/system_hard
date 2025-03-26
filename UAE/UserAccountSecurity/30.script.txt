# Define the privilege to remove
$Privilege = "SeTcbPrivilege"

try {
    # Get current accounts/groups assigned the privilege
    $CurrentAccounts = (Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True").Name
    $RemovedAccounts = @()

    foreach ($Account in $CurrentAccounts) {
        # Remove privilege from the account
        secedit /export /cfg C:\Windows\Temp\secpol.cfg
        (Get-Content C:\Windows\Temp\secpol.cfg) -replace "$Privilege = .*", "$Privilege = " | Set-Content C:\Windows\Temp\secpol.cfg
        secedit /configure /db C:\Windows\security\local.sdb /cfg C:\Windows\Temp\secpol.cfg /areas USER_RIGHTS
        Remove-Item C:\Windows\Temp\secpol.cfg -Force

        $RemovedAccounts += $Account
    }

    Write-Output "Removed 'Act as part of the operating system' from the following accounts: $($RemovedAccounts -join ', ')"
} catch {
    Write-Output "Failed to remove 'Act as part of the operating system' privilege: $_"
}
