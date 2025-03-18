# Registry path for UAC settings
$uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

try {
    # Set elevation prompt behavior for administrators to "Prompt for consent on the secure desktop"
    Set-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord -Force

    # Ensure the secure desktop is enabled for elevation prompts
    Set-ItemProperty -Path $uacPath -Name "PromptOnSecureDesktop" -Value 1 -Type DWord -Force

    Write-Output "UAC elevation prompt for administrators is now set to 'Prompt for consent on the secure desktop'."
    Write-Output "A system restart may be required for changes to take effect."
} catch {
    Write-Output "Failed to apply UAC elevation prompt settings: $_"
}
