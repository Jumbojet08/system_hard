# Set Password Policy Settings
secedit /configure /db c:\windows\security\local.sdb /cfg c:\windows\security\templates\secpol.cfg /areas SECURITYPOLICY

# Define Password Policy Parameters
$PasswordPolicies = @{
    "MinimumPasswordLength"         = 12    # Minimum length of 12 characters
    "MaximumPasswordAge"            = 60    # Maximum password age (days)
    "MinimumPasswordAge"            = 1     # Minimum password age (days)
    "PasswordHistorySize"           = 24    # Remember last 24 passwords
    "ComplexityEnabled"             = 1     # Require uppercase, lowercase, number, symbol
    "LockoutThreshold"              = 5     # Account lockout after 5 failed attempts
    "LockoutDuration"               = 15    # Lockout duration (minutes)
    "ResetLockoutCountAfter"        = 15    # Reset failed attempts count after 15 minutes
}

# Apply Password Policies
foreach ($Policy in $PasswordPolicies.Keys) {
    net accounts /$Policy:$($PasswordPolicies[$Policy])
}

# Ensure Audit Policies for Account Lockouts
auditpol /set /category:"Logon/Logoff" /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /category:"Account Management" /subcategory:"User Account Management" /success:enable /failure:enable

# Enforce Password Policy Immediately
gpupdate /force
