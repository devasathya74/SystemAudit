function Get-SecurityAudit {
    $recs = @()
    $defender = Invoke-SafeCommand { Get-MpComputerStatus } $null
    $firewall = Invoke-SafeCommand { Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction } @()
    $uac = Read-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Default $null
    $smb = Invoke-SafeCommand { Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol } $null
    $rdp = Read-RegistryValue -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Default $null
    $guest = Invoke-SafeCommand { Get-LocalUser -Name Guest } $null
    $mpPreference = Invoke-SafeCommand { Get-MpPreference } $null
    $exclusions = if ($mpPreference) { @($mpPreference.ExclusionPath) } else { @() }
    $executionPolicy = Invoke-SafeCommand { Get-ExecutionPolicy -List } @()
    $bitlocker = Invoke-SafeCommand { Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionPercentage } @()
    $secureBoot = Invoke-SafeCommand { Confirm-SecureBootUEFI } $null
    $deviceGuard = Invoke-SafeCommand { Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard } $null
    $tamperProtection = Read-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -Default $null
    $credentialGuard = if ($deviceGuard) { @($deviceGuard.SecurityServicesRunning) -contains 1 } else { $null }
    $hvci = if ($deviceGuard) { @($deviceGuard.SecurityServicesRunning) -contains 2 } else { $null }
    $vbsEnabled = if ($deviceGuard) { [int]$deviceGuard.VirtualizationBasedSecurityStatus -eq 2 } else { $null }

    if ($defender -and -not $defender.RealTimeProtectionEnabled) {
        $recs += New-Recommendation -Issue "Defender Real-Time Protection Disabled" -Severity CRITICAL -Description "Microsoft Defender real-time protection is disabled." -Impact "Endpoint loses primary malware prevention and telemetry." -Recommendation "Re-enable Defender real-time protection and investigate why it was disabled." -Fix "Set-MpPreference -DisableRealtimeMonitoring `$false"
    }
    foreach ($profile in @($firewall)) {
        if (-not $profile.Enabled) {
            $recs += New-Recommendation -Issue "Firewall Profile Disabled: $($profile.Name)" -Severity HIGH -Description "Windows Firewall is disabled for the $($profile.Name) profile." -Impact "Inbound exposure is increased and policy enforcement is weakened." -Recommendation "Enable firewall profiles and manage allow rules centrally." -Fix "Set-NetFirewallProfile -Profile $($profile.Name) -Enabled True"
        }
    }
    if ($uac -eq 0) {
        $recs += New-Recommendation -Issue "UAC Disabled" -Severity HIGH -Description "User Account Control is disabled." -Impact "Privilege boundaries are weakened for local compromise and malware execution." -Recommendation "Enable UAC and validate application compatibility." -Fix "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1"
    }
    if ($smb -and $smb.State -eq "Enabled") {
        $recs += New-Recommendation -Issue "SMBv1 Enabled" -Severity HIGH -Description "Legacy SMBv1 protocol is enabled." -Impact "SMBv1 is a known ransomware and lateral movement attack vector." -Recommendation "Disable SMBv1 unless a documented legacy dependency exists." -Fix "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"
    }
    if ($rdp -eq 0) {
        $recs += New-Recommendation -Issue "RDP Enabled" -Severity HIGH -Description "Remote Desktop is enabled." -Impact "RDP increases remote attack surface and brute-force exposure." -Recommendation "Restrict RDP with VPN, NLA, MFA, firewall allow-listing, or disable it." -Fix "Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1"
    }
    if ($guest -and $guest.Enabled) {
        $recs += New-Recommendation -Issue "Guest Account Enabled" -Severity HIGH -Description "Built-in Guest account is enabled." -Impact "Guest access weakens accountability and may allow unauthorized local access." -Recommendation "Disable the Guest account." -Fix "Disable-LocalUser -Name Guest"
    }
    if (@($exclusions).Count -gt 0) {
        $recs += New-Recommendation -Issue "Defender Exclusions Present" -Severity WARNING -Description "Defender exclusions are configured." -Impact "Exclusions can create blind spots for malware and persistence." -Recommendation "Review each exclusion for business justification." -Fix "Get-MpPreference | Select-Object -ExpandProperty ExclusionPath"
    }
    if ($secureBoot -eq $false) {
        $recs += New-Recommendation -Issue "Secure Boot Disabled" -Severity HIGH -Description "Secure Boot validation is disabled or unavailable." -Impact "Boot-chain tampering and unsigned boot components are harder to prevent." -Recommendation "Enable Secure Boot in firmware where supported." -Fix "Confirm-SecureBootUEFI"
    }
    if ($tamperProtection -ne $null -and [int]$tamperProtection -eq 0) {
        $recs += New-Recommendation -Issue "Defender Tamper Protection Disabled" -Severity HIGH -Description "Tamper Protection registry state indicates disabled." -Impact "Local processes may alter Defender configuration more easily." -Recommendation "Enable Tamper Protection through Windows Security or enterprise policy." -Fix ""
    }
    if ($mpPreference -and $mpPreference.EnableControlledFolderAccess -eq 0) {
        $recs += New-Recommendation -Issue "Controlled Folder Access Disabled" -Severity WARNING -Description "Ransomware protection controlled folder access is disabled." -Impact "Protected folders have weaker ransomware write protection." -Recommendation "Evaluate enabling Controlled Folder Access for high-risk endpoints." -Fix "Set-MpPreference -EnableControlledFolderAccess Enabled"
    }
    if ($vbsEnabled -eq $false) {
        $recs += New-Recommendation -Issue "Virtualization Based Security Not Running" -Severity WARNING -Description "VBS is not reported as running." -Impact "Credential and kernel isolation protections may be unavailable." -Recommendation "Enable VBS/HVCI where hardware and workload compatibility allow." -Fix "Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard -ClassName Win32_DeviceGuard"
    }

    return [ordered]@{
        defender = if ($defender) { @{ realTimeProtection = $defender.RealTimeProtectionEnabled; antivirusEnabled = $defender.AntivirusEnabled; signatureAge = $defender.AntivirusSignatureAge; quickScanAge = $defender.QuickScanAge } } else { $null }
        defenderAdvanced = if ($mpPreference) { @{
            asrRules = @($mpPreference.AttackSurfaceReductionRules_Ids)
            asrActions = @($mpPreference.AttackSurfaceReductionRules_Actions)
            controlledFolderAccess = $mpPreference.EnableControlledFolderAccess
            cloudProtection = $mpPreference.MAPSReporting
            submitSamplesConsent = $mpPreference.SubmitSamplesConsent
        } } else { $null }
        firewall = @($firewall)
        uacEnabled = if ($uac -eq $null) { $null } else { [bool]$uac }
        smb1 = if ($smb) { $smb.State } else { "Unknown" }
        rdpEnabled = if ($rdp -eq $null) { $null } else { $rdp -eq 0 }
        guestEnabled = if ($guest) { $guest.Enabled } else { $null }
        defenderExclusions = @($exclusions)
        executionPolicy = @($executionPolicy)
        bitlocker = @($bitlocker)
        secureBoot = $secureBoot
        tamperProtection = $tamperProtection
        credentialGuard = $credentialGuard
        hvci = $hvci
        vbsEnabled = $vbsEnabled
        recommendations = $recs
    }
}
