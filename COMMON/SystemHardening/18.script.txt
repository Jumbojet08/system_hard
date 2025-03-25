# Registry path for UAC settings
$uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

try {
    # Enable UAC
    Set-ItemProperty -Path $uacPath -Name "EnableLUA" -Value 1 -Type DWord -Force

    # Ensure secure desktop prompt is enabled
    Set-ItemProperty -Path $uacPath -Name "PromptOnSecureDesktop" -Value 1 -Type DWord -Force

    # Set "Always Notify" for Admins
    Set-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord -Force

    # Set "Always Notify" for Standard Users
    Set-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorUser" -Value 1 -Type DWord -Force

    Write-Output "UAC has been set to the highest level: 'Always Notify' for both Admins and Users."
    Write-Output "A restart is required for changes to take effect."
} catch {
    Write-Output "Failed to apply UAC settings: $_"
}
