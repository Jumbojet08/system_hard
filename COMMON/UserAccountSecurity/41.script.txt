# Define lockout policy values
$LockoutThreshold = 5       # Number of failed attempts before account lockout
$LockoutDuration = 15       # Lockout duration in minutes
$ResetLockoutCount = 15     # Time before failed attempt counter resets

# Apply Account Lockout Policies
secedit /configure /db C:\Windows\security\local.sdb /cfg C:\Windows\security\templates\lockout.inf /areas SECURITYPOLICY /quiet

# Set policies using Local Security Policy
& net accounts /lockoutthreshold:$LockoutThreshold
& net accounts /lockoutduration:$LockoutDuration
& net accounts /lockoutwindow:$ResetLockoutCount

Write-Output "Account Lockout Policies have been configured."
