function Get-RiskSeverity {
    param([int]$Score)
    if ($Score -le $Global:AuditConfig.Risk.SafeMax) { return "SAFE" }
    if ($Score -le $Global:AuditConfig.Risk.WarningMax) { return "WARNING" }
    if ($Score -le $Global:AuditConfig.Risk.HighMax) { return "HIGH" }
    return "CRITICAL"
}

function Measure-RecommendationRisk {
    param([array]$Recommendations)
    $score = 0
    foreach ($item in @($Recommendations)) {
        $severity = (Get-ObjectProperty -InputObject $item -Name "severity" -Default "INFO").ToString().ToUpperInvariant()
        if ($Global:AuditConfig.Risk.Weights.ContainsKey($severity)) {
            $score += [int]$Global:AuditConfig.Risk.Weights[$severity]
        }
    }
    return [math]::Min(100, $score)
}

function Get-AuditRiskProfile {
    param([Parameter(Mandatory)][hashtable]$AuditData)

    $recommendations = @($AuditData.recommendations)
    $securityRecs = $recommendations | Where-Object { $_.issue -match "Defender|Firewall|UAC|BitLocker|SMB|RDP|Guest|Port|Malware|Persistence|WinRM|Encoded PowerShell|LOLBin|Unsigned|Driver|Crack|Browser Extension" }
    $performanceRecs = $recommendations | Where-Object { $_.issue -match "CPU|RAM|Disk|Pagefile|Storage|Thermal|Battery" }
    $privacyRecs = $recommendations | Where-Object { $_.issue -match "Telemetry|Privacy|Camera|Microphone|Location|Clipboard|Browser" }
    $persistenceRecs = $recommendations | Where-Object { $_.issue -match "Startup|Autorun|Scheduled Task|Service|WMI|Browser Extension|Persistence|Encoded PowerShell" }

    $security = Measure-RecommendationRisk -Recommendations $securityRecs
    $performance = Measure-RecommendationRisk -Recommendations $performanceRecs
    $privacy = Measure-RecommendationRisk -Recommendations $privacyRecs
    $stability = Measure-RecommendationRisk -Recommendations ($recommendations | Where-Object { $_.issue -match "Event|Crash|Service|Update|SMART|Disk" })
    $persistence = Measure-RecommendationRisk -Recommendations $persistenceRecs

    $overall = [math]::Round((($security * 0.32) + ($persistence * 0.25) + ($stability * 0.15) + ($performance * 0.18) + ($privacy * 0.10)), 0)

    $severityDistribution = [ordered]@{
        SAFE = @($recommendations | Where-Object severity -eq "SAFE").Count
        WARNING = @($recommendations | Where-Object severity -eq "WARNING").Count
        HIGH = @($recommendations | Where-Object severity -eq "HIGH").Count
        CRITICAL = @($recommendations | Where-Object severity -eq "CRITICAL").Count
    }
    $criticalCount = [int]$severityDistribution.CRITICAL
    $highCount = [int]$severityDistribution.HIGH
    $warningCount = [int]$severityDistribution.WARNING
    if ($criticalCount -gt 0) { $overall = [math]::Max($overall, 76) }
    elseif ($highCount -ge 3) { $overall = [math]::Max($overall, 58) }
    elseif ($highCount -gt 0) { $overall = [math]::Max($overall, 38) }
    elseif ($warningCount -ge 5) { $overall = [math]::Max($overall, 28) }

    return [ordered]@{
        overall = [int]$overall
        overallSeverity = Get-RiskSeverity -Score $overall
        security = [int]$security
        stability = [int]$stability
        performance = [int]$performance
        privacy = [int]$privacy
        persistence = [int]$persistence
        severityDistribution = $severityDistribution
    }
}
