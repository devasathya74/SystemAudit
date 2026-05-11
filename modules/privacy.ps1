function Get-PrivacyAudit {
    $recs = @()
    $telemetry = Read-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Default $null
    $location = Read-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Default "Unknown"
    $camera = Read-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" -Name "Value" -Default "Unknown"
    $microphone = Read-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" -Name "Value" -Default "Unknown"
    $clipboard = Read-RegistryValue -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -Default $null

    if ($telemetry -eq $null) {
        $recs += New-Recommendation -Issue "Telemetry Policy Not Centrally Defined" -Severity WARNING -Description "Windows telemetry policy is not explicitly configured in local policy." -Impact "Privacy posture may depend on defaults or user settings." -Recommendation "Define telemetry policy through enterprise configuration management." -Fix "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Force"
    }
    return [ordered]@{
        telemetry = $telemetry
        location = $location
        camera = $camera
        microphone = $microphone
        clipboardHistory = $clipboard
        recommendations = $recs
    }
}
