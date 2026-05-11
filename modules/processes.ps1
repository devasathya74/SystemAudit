function Get-ProcessIntelligence {
    $recs = @()
    $processes = Invoke-SafeCommand {
        Get-CimInstance Win32_Process
    } @()
    if (@($processes).Count -eq 0) {
        $processes = Invoke-SafeCommand {
            Get-Process | ForEach-Object {
                [pscustomobject]@{
                    ProcessId = $_.Id
                    ParentProcessId = $null
                    Name = if ($_.ProcessName -like "*.exe") { $_.ProcessName } else { "$($_.ProcessName).exe" }
                    ExecutablePath = $_.Path
                    CommandLine = $_.Path
                    CreationDate = $null
                }
            }
        } @()
    }
    $perf = @{}
    Invoke-SafeCommand {
        Get-Process | ForEach-Object {
            $perf[[int]$_.Id] = @{ cpu = $_.CPU; memory = $_.WorkingSet64; startTime = (Invoke-SafeCommand { $_.StartTime } $null) }
        }
    } | Out-Null
    $owners = @{}
    foreach ($proc in @($processes | Where-Object { $_.CimClass } | Select-Object -First 300)) {
        $owner = Invoke-SafeCommand { Invoke-CimMethod -InputObject $proc -MethodName GetOwner } $null
        if ($owner -and $owner.User) { $owners[[int]$proc.ProcessId] = "$($owner.Domain)\$($owner.User)" }
    }

    $rows = @()
    foreach ($proc in @($processes)) {
        $path = [string]$proc.ExecutablePath
        $cmd = [string]$proc.CommandLine
        $signature = Get-FileSignatureInfo -Path $path
        $signals = Get-CommandRiskSignals -CommandLine "$($proc.Name) $cmd $path"
        $nameLower = ([string]$proc.Name).ToLowerInvariant()
        if ($Global:AuditConfig.Suspicious.ProcessNames -contains $nameLower.Replace(".exe", "")) { $signals += "KnownSuspiciousProcess" }
        if ($nameLower -in @("rundll32.exe", "mshta.exe", "wscript.exe", "cscript.exe", "regsvr32.exe") -and $cmd -match "http|https|AppData|Temp|Users\\Public") {
            $signals += "LOLBinAbusePattern"
        }
        if ($nameLower -match "powershell|pwsh" -and $cmd.ToLowerInvariant() -match "-enc|-encodedcommand|hidden|bypass|frombase64string") {
            $signals += "EncodedPowerShell"
        }
        if (Test-SuspiciousPath -Path $path) { $signals += "TempOrUserWritableExecution" }
        $severity = Get-RiskFromSignals -Signals $signals -SignatureStatus $signature.status
        $perfRow = $perf[[int]$proc.ProcessId]
        $row = [ordered]@{
            name = $proc.Name
            pid = $proc.ProcessId
            parentPid = $proc.ParentProcessId
            commandLine = $cmd
            path = $path
            cpu = if ($perfRow) { [math]::Round([double](Get-ValueOrDefault -Value $perfRow.cpu -Default 0), 2) } else { 0 }
            ram = if ($perfRow) { Convert-Bytes $perfRow.memory } else { "Unknown" }
            ramBytes = if ($perfRow) { $perfRow.memory } else { 0 }
            networkUsage = "Correlate with active connections"
            signatureStatus = $signature.status
            signer = $signature.signer
            user = $owners[[int]$proc.ProcessId]
            startTime = if ($perfRow -and $perfRow.startTime) { ([datetime]$perfRow.startTime).ToString("s") } else { "" }
            severity = $severity
            riskSignals = @($signals | Select-Object -Unique)
        }
        $rows += $row
        if ($row.riskSignals -match "EncodedPowerShell") {
            $recs += New-Recommendation -Issue "Encoded PowerShell Execution" -Severity CRITICAL -Description "Process $($proc.ProcessId) is running PowerShell with encoded/hidden/bypass indicators." -Impact "Encoded PowerShell is frequently used for payload staging, evasion, and credential theft." -Recommendation "Capture command line, parent process, script block logs, and isolate if unauthorized." -Fix "Stop-Process -Id $($proc.ProcessId) -WhatIf"
        } elseif ($severity -eq "HIGH") {
            $recs += New-Recommendation -Issue "Suspicious Process Execution" -Severity HIGH -Description "$($proc.Name) has signals: $(@($signals) -join ', ')." -Impact "Suspicious process behavior may indicate LOLBin abuse, temp execution, or unauthorized tooling." -Recommendation "Validate parent process, binary signature, hash reputation, and network connections." -Fix "Get-CimInstance Win32_Process -Filter `"ProcessId=$($proc.ProcessId)`" | Select-Object *"
        }
    }

    return [ordered]@{
        processes = @($rows | Sort-Object @{ Expression = { Get-SeverityWeight $_.severity }; Descending = $true }, @{ Expression = { $_.ramBytes }; Descending = $true } | Select-Object -First 500)
        suspiciousProcesses = @($rows | Where-Object { $_.severity -in @("HIGH", "CRITICAL") })
        topResourceUsage = @($rows | Sort-Object @{ Expression = { $_.ramBytes }; Descending = $true } | Select-Object -First 25)
        recommendations = $recs
    }
}
