# Enable Windows Firewall for all profiles
Write-Output "Enabling Windows Firewall..."
Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True

# Block all inbound connections by default
Write-Output "Blocking all inbound connections by default..."
Set-NetFirewallProfile -Profile Domain, Private, Public -DefaultInboundAction Block

# Allow all outbound connections by default (modify if needed)
Write-Output "Allowing all outbound connections..."
Set-NetFirewallProfile -Profile Domain, Private, Public -DefaultOutboundAction Allow



Write-Output "Firewall configuration completed."
