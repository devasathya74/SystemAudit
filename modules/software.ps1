function Get-SoftwareAudit {
    $recs = @()
    $paths = @(
        @{ path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"; architecture = "x64/system" },
        @{ path = "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"; architecture = "x86" },
        @{ path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"; architecture = "user" }
    )
    $running = Invoke-SafeCommand { Get-Process | Select-Object ProcessName, Path, CPU, WorkingSet64 } @()
    $startupCommands = @()
    foreach ($key in @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run")) {
        $props = Invoke-SafeCommand { Get-ItemProperty -LiteralPath $key -ErrorAction Stop } $null
        if ($props) {
            $startupCommands += @($props.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object { [string]$_.Value })
        }
    }

    $apps = foreach ($entry in $paths) {
        Invoke-SafeCommand {
            Get-ItemProperty $entry.path -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName } |
                ForEach-Object {
                    $installLocation = [string]$_.InstallLocation
                    $displayIcon = [string]$_.DisplayIcon
                    $displayName = [string]$_.DisplayName
                    $exe = Get-ExecutablePathFromCommand -CommandLine $displayIcon
                    if (-not $exe -and $installLocation -and (Test-Path -LiteralPath $installLocation)) {
                        $exe = @(Get-ChildItem -LiteralPath $installLocation -Filter *.exe -File -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName)[0]
                    }
                    $signature = Get-FileSignatureInfo -Path $exe
                    $runningMatches = @($running | Where-Object { $_.Path -and $installLocation -and $_.Path -like "$installLocation*" })
                    $startupEnabled = @($startupCommands | Where-Object { ($displayName -and ($_.ToLowerInvariant()).Contains($displayName.ToLowerInvariant())) -or ($installLocation -and $_ -like "$installLocation*") }).Count -gt 0
                    $signals = Get-CommandRiskSignals -CommandLine "$($_.DisplayName) $installLocation $displayIcon"
                    $severity = Get-RiskFromSignals -Signals $signals -SignatureStatus $signature.status
                    if ($signature.isSigned -eq $false -and (Test-SuspiciousPath -Path $exe)) { $severity = "HIGH"; $signals += "UnsignedInUserWritablePath" }
                    [ordered]@{
                        name = $_.DisplayName
                        version = $_.DisplayVersion
                        publisher = $_.Publisher
                        installDate = $_.InstallDate
                        installLocation = $installLocation
                        sizeMb = if ($_.EstimatedSize) { [math]::Round(([double]$_.EstimatedSize / 1024), 2) } else { $null }
                        architecture = $entry.architecture
                        running = ($runningMatches.Count -gt 0)
                        startupEnabled = $startupEnabled
                        signatureStatus = $signature.status
                        signer = $signature.signer
                        signed = $signature.isSigned
                        microsoftTrusted = $signature.isMicrosoft -or ([string]$_.Publisher -like "*Microsoft*")
                        networkAccess = "Correlate with process telemetry"
                        highResourceUsage = @($runningMatches | Where-Object { ($_.CPU -gt 300) -or ($_.WorkingSet64 -gt 500MB) }).Count -gt 0
                        severity = $severity
                        riskSignals = @($signals | Select-Object -Unique)
                    }
                }
        } @()
    }
    $apps = @($apps | Sort-Object name -Unique)
    $unknown = @($apps | Where-Object { [string]::IsNullOrWhiteSpace($_.publisher) })
    $unsignedRisk = @($apps | Where-Object { $_.signed -eq $false -and (Test-SuspiciousPath -Path $_.installLocation) })
    $cracks = @($apps | Where-Object { ($_.riskSignals -join " ") -match "CrackIndicator" })
    $oldJava = @($apps | Where-Object { $_.name -match "Java" -and $_.version -match "^(6|7|8)\." })
    if ($unknown.Count -gt 0) {
        $recs += New-Recommendation -Issue "Software With Unknown Publisher" -Severity WARNING -Description "$($unknown.Count) installed applications do not report a publisher." -Impact "Unknown publishers reduce supply-chain and asset assurance." -Recommendation "Review unsigned or unknown applications and remove unauthorized software." -Fix ""
    }
    foreach ($app in $unsignedRisk | Select-Object -First 10) {
        $recs += New-Recommendation -Issue "Unsigned Software in Suspicious Location" -Severity HIGH -Description "$($app.name) appears unsigned and installed under a user-writable or staging path." -Impact "Unsigned binaries in weak locations are common malware and persistence patterns." -Recommendation "Validate the binary hash/signature and remove if unauthorized." -Fix "Get-AuthenticodeSignature -LiteralPath '$($app.installLocation)'"
    }
    foreach ($app in $cracks | Select-Object -First 10) {
        $recs += New-Recommendation -Issue "Crack Tool Indicator Detected" -Severity CRITICAL -Description "$($app.name) or its install metadata matches crack/keygen/activator indicators." -Impact "Crack tools frequently carry credential theft, loaders, and persistence payloads." -Recommendation "Isolate the endpoint if needed, remove the software, and run full malware triage." -Fix ""
    }
    foreach ($app in $oldJava | Select-Object -First 10) {
        $recs += New-Recommendation -Issue "Old Java Version Detected" -Severity HIGH -Description "$($app.name) $($app.version) appears to be an old Java runtime." -Impact "Old Java versions are high-value exploit targets." -Recommendation "Remove legacy Java or update to a supported runtime." -Fix ""
    }
    return [ordered]@{
        applicationCount = $apps.Count
        unknownPublisherCount = $unknown.Count
        unsignedSuspiciousCount = $unsignedRisk.Count
        crackIndicatorCount = $cracks.Count
        riskyApplications = @($apps | Where-Object { $_.severity -in @("WARNING", "HIGH", "CRITICAL") })
        applications = @($apps | Select-Object -First 500)
        recommendations = $recs
    }
}
