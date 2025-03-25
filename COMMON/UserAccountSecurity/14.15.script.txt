# Define new Administrator name
$NewAdminName = "SecAdmin"  # Change this to the desired name

# Rename Built-in Administrator Account
$AdminAccount = Get-WmiObject Win32_UserAccount | Where-Object { $_.SID -like "S-1-5-*-500" }
if ($AdminAccount) {
    Rename-LocalUser -Name $AdminAccount.Name -NewName $NewAdminName
}

# Disable Built-in Guest Account
$GuestAccount = Get-WmiObject Win32_UserAccount | Where-Object { $_.SID -like "S-1-5-*-501" }
if ($GuestAccount) {
    Disable-LocalUser -Name $GuestAccount.Name
}

# Confirm Changes
Write-Host "Built-in Administrator account renamed to: $NewAdminName" -ForegroundColor Green
Write-Host "Built-in Guest account has been disabled." -ForegroundColor Green
