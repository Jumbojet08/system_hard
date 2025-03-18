# Enable Windows Firewall for all profiles
Write-Output "Enabling Windows Firewall..."
Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True

# Block all inbound connections by default
Write-Output "Blocking all inbound connections by default..."
Set-NetFirewallProfile -Profile Domain, Private, Public -DefaultInboundAction Block

# Allow all outbound connections by default (modify if needed)
Write-Output "Allowing all outbound connections..."
Set-NetFirewallProfile -Profile Domain, Private, Public -DefaultOutboundAction Allow

# Define necessary ports, programs, and protocols to allow
$rules = @(
    @{Name="Allow HTTP"; Protocol="TCP"; Port=80; Direction="Inbound"; Action="Allow";},
    @{Name="Allow HTTPS"; Protocol="TCP"; Port=443; Direction="Inbound"; Action="Allow";},
    @{Name="Allow RDP"; Protocol="TCP"; Port=3389; Direction="Inbound"; Action="Allow";},
    @{Name="Allow DNS"; Protocol="UDP"; Port=53; Direction="Inbound"; Action="Allow";},
    @{Name="Allow ICMP"; Protocol="ICMPv4"; Port=-1; Direction="Inbound"; Action="Allow";},
    @{Name="Allow Custom App"; Program="C:\Program Files\CustomApp\app.exe"; Direction="Inbound"; Action="Allow";}
)

# Apply firewall rules
foreach ($rule in $rules) {
    if ($rule.Program) {
        # Allow a specific program
        New-NetFirewallRule -DisplayName $rule.Name -Direction $rule.Direction -Action $rule.Action -Program $rule.Program -Profile Any
        Write-Output "Allowed program: $($rule.Program)"
    } else {
        # Allow specific port/protocol
        New-NetFirewallRule -DisplayName $rule.Name -Direction $rule.Direction -Action $rule.Action -Protocol $rule.Protocol -LocalPort $rule.Port -Profile Any
        Write-Output "Allowed $($rule.Protocol) on port $($rule.Port)"
    }
}

Write-Output "Firewall configuration completed."
