function Get-ServiceAudit {
    $recs = @()
    $services = Invoke-SafeCommand {
        Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName, StartName, ProcessId
    } @()
    if (@($services).Count -eq 0) {
        $services = Invoke-SafeCommand {
            Get-Service | ForEach-Object {
                [pscustomobject]@{
                    Name = $_.Name
                    DisplayName = $_.DisplayName
                    State = [string]$_.Status
                    StartMode = [string]$_.StartType
                    PathName = (Read-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($_.Name)" -Name "ImagePath" -Default "")
                    StartName = ""
                    ProcessId = $null
                }
            }
        } @()
    }
    $serviceDetails = @()
    $securityServices = @("WinDefend", "Sense", "WdNisSvc", "MpsSvc", "EventLog", "SecurityHealthService")
    foreach ($svc in @($services)) {
        $path = [string]$svc.PathName
        $exe = Get-ExecutablePathFromCommand -CommandLine $path
        $signals = Get-CommandRiskSignals -CommandLine $path
        $trust = Get-TrustProfile -Path $exe -Publisher $svc.StartName -Signals $signals
        $signature = $trust.signature
        $isUnquoted = ($path -match "\s" -and -not $path.Trim().StartsWith('"') -and $exe -match "\s")
        $isDelayed = (Read-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)" -Name "DelayedAutoStart" -Default 0) -eq 1
        $isMicrosoftSecurityService = ($securityServices -contains $svc.Name) -or ($signature.isMicrosoft -and $svc.DisplayName -match "Defender|Security|Firewall|Event Log|Microsoft")
        $severity = Get-RiskFromSignals -Signals $signals -SignatureStatus $signature.status -MicrosoftTrusted $trust.microsoftTrusted
        if ($isMicrosoftSecurityService -and $svc.State -eq "Running") {
            $severity = "SAFE"
            $signals = @($signals | Where-Object { $_ -ne "UserWritablePath" })
        }
        if ($svc.StartMode -eq "Auto" -and (Test-SuspiciousPath -Path $path) -and -not $trust.microsoftTrusted) {
            $severity = "WARNING"
            $recs += New-Recommendation -Issue "Auto Service Uses Suspicious Path" -Severity WARNING -Description "$($svc.Name) starts from a user-writable or staging path." -Impact "Services running from weak locations can indicate persistence or tampering." -Recommendation "Validate binary signature and move approved services to protected paths." -Fix "Get-CimInstance Win32_Service -Filter `"Name='$($svc.Name)'`""
        }
        if ($isUnquoted -and -not $trust.microsoftTrusted) {
            $severity = "HIGH"
            $recs += New-Recommendation -Issue "Unquoted Service Path" -Severity HIGH -Description "$($svc.Name) has an unquoted binary path containing spaces." -Impact "Unquoted service paths can permit privilege escalation through path hijacking." -Recommendation "Quote the service binary path and validate directory ACLs." -Fix "sc.exe qc `"$($svc.Name)`""
        }
        if ($svc.StartMode -eq "Auto" -and $signature.isSigned -eq $false) {
            $severity = "HIGH"
            $recs += New-Recommendation -Issue "Unsigned AutoStart Service" -Severity HIGH -Description "$($svc.Name) is configured for automatic start and its binary is unsigned." -Impact "Unsigned services survive reboot and can be used as durable persistence." -Recommendation "Disable and investigate immediately if not business-approved." -Fix "Set-Service -Name '$($svc.Name)' -StartupType Disabled"
        }
        if ($securityServices -contains $svc.Name -and $svc.State -ne "Running") {
            $severity = "HIGH"
            $recs += New-Recommendation -Issue "Security Service Not Running" -Severity HIGH -Description "$($svc.Name) is not running." -Impact "Disabled security telemetry or enforcement can blind detection and prevention." -Recommendation "Restore the service and investigate local tampering." -Fix "Start-Service -Name '$($svc.Name)'"
        }
        $serviceDetails += [ordered]@{
            name = $svc.Name
            displayName = $svc.DisplayName
            state = $svc.State
            startMode = $svc.StartMode
            delayedAutoStart = $isDelayed
            account = $svc.StartName
            pid = $svc.ProcessId
            path = $path
            executable = $exe
            signatureStatus = $signature.status
            signer = $signature.signer
            signed = $signature.isSigned
            microsoftTrusted = $trust.microsoftTrusted
            trustScore = $trust.score
            trustClassification = if ($isMicrosoftSecurityService -and $svc.State -eq "Running") { "Microsoft Signed Security Service" } else { $trust.classification }
            unquotedPath = $isUnquoted
            severity = $severity
            riskSignals = @($signals | Select-Object -Unique)
        }
    }
    $highPriority = @($serviceDetails | Where-Object {
        $_.severity -in @("WARNING", "HIGH", "CRITICAL") -or
        ($_.startMode -eq "Auto" -and -not $_.microsoftTrusted) -or
        $_.signed -eq $false -or
        $_.riskSignals.Count -gt 0
    })
    return @{
        services = @($serviceDetails | Sort-Object @{ Expression = { Get-SeverityWeight $_.severity }; Descending = $true }, name | Select-Object -First 350)
        highPriorityServices = @($highPriority | Sort-Object @{ Expression = { Get-SeverityWeight $_.severity }; Descending = $true }, @{ Expression = "trustScore"; Descending = $true }, name)
        collapsedTrustedServices = @($serviceDetails | Where-Object { $_.microsoftTrusted -and $_.severity -in @("SAFE", "INFO") }).Count
        unsignedServices = @($serviceDetails | Where-Object { $_.signed -eq $false })
        autoServices = @($serviceDetails | Where-Object { $_.startMode -eq "Auto" })
        recommendations = $recs
    }
}
