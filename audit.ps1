param(
    [switch]$NoBrowser,
    [switch]$IncludePublicIp
)

$ErrorActionPreference = "Continue"

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $ScriptRoot "core/config.ps1")
. (Join-Path $ScriptRoot "core/logger.ps1")
. (Join-Path $ScriptRoot "core/helpers.ps1")
. (Join-Path $ScriptRoot "core/risk-engine.ps1")

Initialize-AuditEnvironment -RootPath $ScriptRoot
Initialize-Logger -LogDirectory $Global:AuditConfig.Paths.Logs -ConsoleEnabled $true

Write-Log -Level INFO -Message "Enterprise Windows System Audit started"

$isAdmin = Test-IsAdministrator
if (-not $isAdmin) {
    Write-Log -Level WARN -Message "Running without administrative privileges; privileged checks will degrade gracefully"
}

$moduleFiles = @(
    "system.ps1", "cpu.ps1", "ram.ps1", "disk.ps1", "battery.ps1", "network.ps1",
    "ports.ps1", "security.ps1", "startup.ps1", "services.ps1", "browser.ps1",
    "privacy.ps1", "updates.ps1", "software.ps1", "processes.ps1", "drivers.ps1",
    "eventlogs.ps1", "malware.ps1"
)

foreach ($moduleFile in $moduleFiles) {
    $path = Join-Path $ScriptRoot "modules/$moduleFile"
    try {
        . $path
        Write-Log -Level OK -Message "Loaded module $moduleFile"
    } catch {
        Write-Log -Level ERROR -Message "Failed to load module $moduleFile" -Data @{ error = $_.Exception.Message }
    }
}

function Invoke-Collector {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Script
    )

    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log -Level INFO -Message "$Name collector started"
    try {
        $result = & $Script
        $timer.Stop()
        Write-Log -Level OK -Message "$Name collector completed" -Data @{ milliseconds = $timer.ElapsedMilliseconds }
        return $result
    } catch {
        $timer.Stop()
        Write-Log -Level ERROR -Message "$Name collector failed" -Data @{ error = $_.Exception.Message; milliseconds = $timer.ElapsedMilliseconds }
        return @{
            status = "Failed"
            error = $_.Exception.Message
            recommendations = @()
        }
    }
}

$runId = New-AuditRunId
$generatedAt = Get-AuditTimestamp

$system = Invoke-Collector -Name "System" -Script { Get-SystemAuditInfo }
$cpu = Invoke-Collector -Name "CPU" -Script { Get-CpuHealth }
$ram = Invoke-Collector -Name "RAM" -Script { Get-RamAnalysis }
$disk = Invoke-Collector -Name "Disk" -Script { Get-DiskHealth }
$battery = Invoke-Collector -Name "Battery" -Script { Get-BatteryHealth }
$network = Invoke-Collector -Name "Network" -Script { Get-NetworkAnalysis -IncludePublicIp:$IncludePublicIp }
$ports = Invoke-Collector -Name "Ports" -Script { Get-PortExposure }
$security = Invoke-Collector -Name "Security" -Script { Get-SecurityAudit }
$startup = Invoke-Collector -Name "Startup" -Script { Get-StartupPersistence }
$services = Invoke-Collector -Name "Services" -Script { Get-ServiceAudit }
$browser = Invoke-Collector -Name "Browser" -Script { Get-BrowserSecurity }
$privacy = Invoke-Collector -Name "Privacy" -Script { Get-PrivacyAudit }
$updates = Invoke-Collector -Name "Updates" -Script { Get-UpdateAudit }
$software = Invoke-Collector -Name "Software" -Script { Get-SoftwareAudit }
$processes = Invoke-Collector -Name "Processes" -Script { Get-ProcessIntelligence }
$drivers = Invoke-Collector -Name "Drivers" -Script { Get-DriverIntelligence }
$eventLogs = Invoke-Collector -Name "Event Logs" -Script { Get-EventLogAnalysis }
$malwareIndicators = Invoke-Collector -Name "Malware Indicators" -Script { Get-MalwareIndicators }

$recommendations = @()
foreach ($section in @($cpu, $ram, $disk, $battery, $network, $ports, $security, $startup, $services, $browser, $privacy, $updates, $software, $processes, $drivers, $eventLogs, $malwareIndicators)) {
    if ($null -ne $section -and $null -ne $section.recommendations) {
        $recommendations += @($section.recommendations)
    }
}

$risk = Get-AuditRiskProfile -AuditData @{
    cpu = $cpu
    ram = $ram
    disk = $disk
    network = $network
    ports = $ports
    security = $security
    startup = $startup
    services = $services
    browser = $browser
    privacy = $privacy
    updates = $updates
    software = $software
    processes = $processes
    drivers = $drivers
    eventLogs = $eventLogs
    malwareIndicators = $malwareIndicators
    recommendations = $recommendations
}

$persistence = @()
$persistence += @($startup.entries)
$persistence += @($services.autoServices | ForEach-Object { [ordered]@{ type = "Auto Service"; name = $_.name; command = $_.path; location = "Service Control Manager"; severity = $_.severity; riskSignals = $_.riskSignals } })
$persistence += @($browser.extensions | Where-Object { $_.severity -ne "INFO" } | ForEach-Object { [ordered]@{ type = "Browser Extension"; name = $_.name; command = $_.id; location = $_.browser; severity = $_.severity; riskSignals = $_.riskSignals } })
$persistence = @($persistence | Where-Object { $_ } | Sort-Object @{ Expression = { Get-SeverityWeight $_.severity }; Descending = $true }, type, name)

$threatIndicators = @()
$threatIndicators += @($processes.suspiciousProcesses | ForEach-Object { [ordered]@{ type = "Process"; name = $_.name; detail = $_.commandLine; severity = $_.severity; riskSignals = $_.riskSignals } })
$threatIndicators += @($malwareIndicators.indicators)
$threatIndicators += @($drivers.drivers | Where-Object { $_.severity -in @("HIGH", "CRITICAL") } | ForEach-Object { [ordered]@{ type = "Driver"; name = $_.name; detail = $_.path; severity = $_.severity; riskSignals = $_.riskSignals } })
$threatIndicators += @($software.riskyApplications | Where-Object { $_.severity -in @("HIGH", "CRITICAL") } | ForEach-Object { [ordered]@{ type = "Application"; name = $_.name; detail = $_.installLocation; severity = $_.severity; riskSignals = $_.riskSignals } })
$threatIndicators = @($threatIndicators | Where-Object { $_ } | Sort-Object @{ Expression = { Get-SeverityWeight $_.severity }; Descending = $true }, type, name)

$performanceCorrelations = @()
foreach ($proc in @($processes.topResourceUsage | Where-Object { $_.ramBytes -gt 300MB -or $_.cpu -gt 300 })) {
    $matches = @($software.applications | Where-Object { $_.installLocation -and $proc.path -and $proc.path -like "$($_.installLocation)*" } | Select-Object -First 1)
    $matchedApp = if ($matches.Count -gt 0) { $matches[0] } else { $null }
    $loadsAtStartup = ($matchedApp -and $matchedApp.startupEnabled) -or (@($persistence | Where-Object { $_.command -and $proc.path -and $_.command -like "*$($proc.path)*" }).Count -gt 0)
    if ($loadsAtStartup -or $proc.severity -ne "INFO") {
        $performanceCorrelations += [ordered]@{
            process = $proc.name
            pid = $proc.pid
            application = if ($matchedApp) { $matchedApp.name } else { "" }
            resource = "CPU=$($proc.cpu), RAM=$($proc.ram)"
            loadsAtStartup = [bool]$loadsAtStartup
            signatureStatus = $proc.signatureStatus
            severity = if ($proc.severity -ne "INFO") { $proc.severity } elseif ($loadsAtStartup) { "WARNING" } else { "INFO" }
            explanation = "High resource process correlated with startup/persistence or suspicious execution signals."
        }
    }
}

$persistenceTimeline = @(
    @{ phase = "Boot"; count = @($services.autoServices | Where-Object { $_.startMode -in @("Auto", "Boot", "System") }).Count; severity = "INFO"; description = "Auto, boot, and system services initialize" },
    @{ phase = "Services Started"; count = @($services.autoServices).Count; severity = "INFO"; description = "Service Control Manager launches automatic services" },
    @{ phase = "Startup Apps Loaded"; count = @($startup.entries | Where-Object { $_.type -match "Registry Run|Startup Folder" }).Count; severity = "INFO"; description = "Registry and startup-folder autoruns execute" },
    @{ phase = "Scheduled Tasks Triggered"; count = @($startup.scheduledTasks).Count; severity = "INFO"; description = "Boot, logon, and scheduled tasks evaluate triggers" },
    @{ phase = "Browser Extensions Loaded"; count = @($browser.extensions).Count; severity = "INFO"; description = "Browser profile and policy extensions load with browser sessions" }
)

$unsignedBinaries = @()
$unsignedBinaries += @($services.services | Where-Object { $_.signed -eq $false } | ForEach-Object { [ordered]@{ type = "Service"; name = $_.name; path = $_.executable; severity = $_.severity; trustScore = $_.trustScore } })
$unsignedBinaries += @($drivers.drivers | Where-Object { $_.signed -eq $false } | ForEach-Object { [ordered]@{ type = "Driver"; name = $_.name; path = $_.normalizedPath; severity = $_.severity; trustScore = 80 } })
$unsignedBinaries += @($processes.processes | Where-Object { $_.signatureStatus -notin @("Valid", "Unknown") } | ForEach-Object { [ordered]@{ type = "Process"; name = $_.name; path = $_.path; severity = $_.severity; trustScore = 70 } })

$health = [ordered]@{
    system = @{
        osCollected = -not [string]::IsNullOrWhiteSpace($system.os)
        cpuCollected = -not [string]::IsNullOrWhiteSpace($system.cpuModel)
        ramCollected = $system.installedRam -ne "Unknown" -and $system.installedRam -ne "0.00 B"
        collectionSource = $system.collectionQuality.source
    }
    disk = $disk.healthSummary
    memory = @{
        total = $ram.total
        usedPercent = $ram.usedPercent
        pressure = $ram.memoryPressure
        collectionSource = $ram.collectionQuality.source
    }
    ports = $ports.exposureSummary
    security = @{
        secureBoot = $security.secureBoot
        vbsEnabled = $security.vbsEnabled
        hvci = $security.hvci
        credentialGuard = $security.credentialGuard
        tamperProtection = $security.tamperProtection
    }
}

$previousReport = Get-ChildItem -LiteralPath $Global:AuditConfig.Paths.Reports -Filter "audit-*.json" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
$historicalDiff = [ordered]@{ baseline = ""; newServices = @(); newPorts = @(); newDrivers = @(); newStartup = @() }
if ($previousReport) {
    $previous = Invoke-SafeCommand { Get-Content -LiteralPath $previousReport.FullName -Raw | ConvertFrom-Json } $null
    if ($previous) {
        $historicalDiff.baseline = $previousReport.Name
        $oldServiceNames = @($previous.services.services | ForEach-Object { $_.name })
        $oldPorts = @($previous.ports | ForEach-Object { "$($_.protocol)/$($_.port)/$($_.process)" })
        $oldDrivers = @($previous.drivers | ForEach-Object { $_.name })
        $oldStartup = @($previous.startup | ForEach-Object { "$($_.type)/$($_.name)/$($_.command)" })
        $historicalDiff.newServices = @($services.services | Where-Object { $oldServiceNames -notcontains $_.name } | Select-Object -First 50)
        $historicalDiff.newPorts = @($ports.listeningPorts | Where-Object { $oldPorts -notcontains "$($_.protocol)/$($_.port)/$($_.process)" } | Select-Object -First 50)
        $historicalDiff.newDrivers = @($drivers.drivers | Where-Object { $oldDrivers -notcontains $_.name } | Select-Object -First 50)
        $historicalDiff.newStartup = @($startup.entries | Where-Object { $oldStartup -notcontains "$($_.type)/$($_.name)/$($_.command)" } | Select-Object -First 50)
    }
}

$overview = @{
    runId = $runId
    generatedAt = $generatedAt
    hostname = (Get-ValueOrDefault -Value $system.hostname -Default $env:COMPUTERNAME)
    username = (Get-ValueOrDefault -Value $system.username -Default "$env:USERDOMAIN\$env:USERNAME")
    admin = $isAdmin
    platform = "Enterprise Windows System Audit & Health Intelligence Platform"
    riskSeverity = $risk.overallSeverity
    overallRiskScore = $risk.overall
    recommendationCount = @($recommendations).Count
}

$audit = [ordered]@{
    overview = $overview
    system = $system
    cpu = $cpu
    ram = $ram
    disk = $disk
    battery = $battery
    health = $health
    security = $security
    network = $network
    ports = @($ports.listeningPorts)
    startup = $startup.entries
    services = $services
    highPriorityServices = $services.highPriorityServices
    browser = $browser
    privacy = $privacy
    updates = $updates
    software = $software.applications
    applications = $software.applications
    riskyApplications = $software.riskyApplications
    processes = $processes.processes
    suspiciousProcesses = $processes.suspiciousProcesses
    drivers = $drivers.drivers
    scheduledTasks = $startup.scheduledTasks
    browserExtensions = $browser.extensions
    persistence = $persistence
    persistenceTimeline = $persistenceTimeline
    threatIndicators = $threatIndicators
    performanceCorrelations = $performanceCorrelations
    unsignedBinaries = $unsignedBinaries
    trustAnalysis = @{
        highPriorityServices = @($services.highPriorityServices).Count
        collapsedTrustedServices = $services.collapsedTrustedServices
        unsignedBinaries = @($unsignedBinaries).Count
        microsoftTrustedServices = @($services.services | Where-Object microsoftTrusted -eq $true).Count
    }
    historicalDiff = $historicalDiff
    eventLogs = $eventLogs
    malwareIndicators = $malwareIndicators.indicators
    recommendations = $recommendations | Sort-Object @{ Expression = { Get-SeverityWeight $_.severity }; Descending = $true }, issue
    risk = $risk
    logs = Get-LogEntries
}

$jsonPath = Join-Path $Global:AuditConfig.Paths.Reports "$runId.json"
$reportPath = Join-Path $Global:AuditConfig.Paths.Reports "$runId.html"
$json = $audit | ConvertTo-Json -Depth 12
Set-Content -LiteralPath $jsonPath -Value $json -Encoding UTF8

$templatePath = Join-Path $ScriptRoot "templates/report.html"
$template = Get-Content -LiteralPath $templatePath -Raw
$report = $template.Replace("__AUDIT_JSON_PAYLOAD__", (ConvertTo-SafeHtmlJson -Json $json))
Set-Content -LiteralPath $reportPath -Value $report -Encoding UTF8

Write-Log -Level OK -Message "Report generated" -Data @{ report = $reportPath; json = $jsonPath }

if (-not $NoBrowser) {
    try {
        Start-Process "chrome.exe" $reportPath
    } catch {
        Write-Log -Level WARN -Message "Chrome launch failed; using default file handler" -Data @{ error = $_.Exception.Message }
        Start-Process $reportPath
    }
}

Write-Host ""
Write-Host "Report: $reportPath"
Write-Host "JSON:   $jsonPath"
