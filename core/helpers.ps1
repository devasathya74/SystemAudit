function Test-IsAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Invoke-SafeCommand {
    param(
        [Parameter(Mandatory)][scriptblock]$Script,
        [object]$Default = $null
    )

    try {
        $previousPreference = $ErrorActionPreference
        $previousGlobalPreference = $Global:ErrorActionPreference
        $ErrorActionPreference = "Stop"
        $Global:ErrorActionPreference = "Stop"
        try {
            $result = & $Script 2>$null
            if ($null -eq $result) { return $Default }
            return $result
        } finally {
            $ErrorActionPreference = $previousPreference
            $Global:ErrorActionPreference = $previousGlobalPreference
        }
    } catch {
        Write-Log -Level WARN -Message "Safe command failed" -Data @{ error = $_.Exception.Message }
        return $Default
    }
}

function Convert-Bytes {
    param([Nullable[double]]$Bytes)
    if ($null -eq $Bytes) { return "Unknown" }
    $units = @("B", "KB", "MB", "GB", "TB", "PB")
    $value = [double]$Bytes
    $index = 0
    while ($value -ge 1024 -and $index -lt ($units.Count - 1)) {
        $value = $value / 1024
        $index++
    }
    return ("{0:N2} {1}" -f $value, $units[$index])
}

function ConvertTo-Percent {
    param([double]$Part, [double]$Total)
    if ($Total -le 0) { return 0 }
    return [math]::Round(($Part / $Total) * 100, 2)
}

function Get-AuditTimestamp {
    return (Get-Date).ToString("yyyy-MM-dd HH:mm:ss zzz")
}

function New-AuditRunId {
    return "audit-{0}" -f (Get-Date -Format "yyyyMMdd-HHmmss")
}

function Get-SeverityWeight {
    param([string]$Severity)
    if ([string]::IsNullOrWhiteSpace($Severity)) { $Severity = "INFO" }
    switch ($Severity.ToUpperInvariant()) {
        "CRITICAL" { 4 }
        "HIGH" { 3 }
        "WARNING" { 2 }
        "SAFE" { 1 }
        default { 0 }
    }
}

function Get-ValueOrDefault {
    param(
        [object]$Value,
        [object]$Default
    )
    if ($null -eq $Value) { return $Default }
    return $Value
}

function Get-ObjectProperty {
    param(
        [object]$InputObject,
        [Parameter(Mandatory)][string]$Name,
        [object]$Default = $null
    )
    if ($null -eq $InputObject) { return $Default }
    if ($InputObject -is [System.Collections.IDictionary] -and $InputObject.Contains($Name)) {
        return $InputObject[$Name]
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $Default }
    return $property.Value
}

function Test-SuspiciousPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    foreach ($marker in $Global:AuditConfig.Suspicious.StartupPaths) {
        if ($Path -like "*$marker*") { return $true }
    }
    return $false
}

function Get-ExecutablePathFromCommand {
    param([string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return "" }
    $trimmed = $CommandLine.Trim()
    if ($trimmed.StartsWith('"')) {
        $end = $trimmed.IndexOf('"', 1)
        if ($end -gt 1) { return $trimmed.Substring(1, $end - 1) }
    }
    $candidate = ($trimmed -split "\s+")[0]
    return $candidate.Trim('"')
}

function Get-FileSignatureInfo {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return @{ status = "Unknown"; signer = ""; isSigned = $null; isMicrosoft = $false }
    }
    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        $signer = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { "" }
        return @{
            status = [string]$signature.Status
            signer = $signer
            isSigned = ($signature.Status -eq "Valid")
            isMicrosoft = ($signer -like "*Microsoft*")
        }
    } catch {
        return @{ status = "Unknown"; signer = ""; isSigned = $null; isMicrosoft = $false }
    }
}

function Get-TrustProfile {
    param(
        [string]$Path,
        [string]$Publisher = "",
        [array]$Signals = @()
    )
    $signature = Get-FileSignatureInfo -Path $Path
    $isMicrosoftPath = $Path -like "$env:WINDIR\*" -or $Path -like "$env:ProgramFiles\Windows Defender\*" -or $Path -like "$env:ProgramFiles\Microsoft*"
    $knownVendor = -not [string]::IsNullOrWhiteSpace($Publisher)
    $score = 50
    if ($signature.isMicrosoft -or $Publisher -like "*Microsoft*") { $score -= 40 }
    elseif ($signature.isSigned -eq $true -or $knownVendor) { $score -= 18 }
    if ($signature.isSigned -eq $false) { $score += 35 }
    if ($Signals -match "UserWritablePath|TempOrUserWritableExecution|UnsignedInUserWritablePath") { $score += 25 }
    if ($Signals -match "LOLBin|ScriptToken|EncodedPowerShell") { $score += 28 }
    if ($Signals -match "CrackIndicator|KnownSuspiciousProcess|WMIPersistence") { $score += 45 }
    if ($isMicrosoftPath -and ($signature.isMicrosoft -or $Publisher -like "*Microsoft*")) { $score -= 20 }
    $score = [math]::Max(0, [math]::Min(100, $score))
    $classification = if ($score -ge 80) { "Malicious/Suspicious" } elseif ($score -ge 60) { "High Risk" } elseif ($score -ge 35) { "Review" } else { "Trusted" }
    return @{
        score = [int]$score
        classification = $classification
        signature = $signature
        microsoftTrusted = ($signature.isMicrosoft -or $Publisher -like "*Microsoft*")
        knownVendor = $knownVendor
    }
}

function Get-CommandRiskSignals {
    param([string]$CommandLine)
    $signals = @()
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $signals }
    $lower = $CommandLine.ToLowerInvariant()
    foreach ($token in $Global:AuditConfig.Suspicious.ScriptTokens) {
        if ($lower.Contains($token)) { $signals += "ScriptToken:$token" }
    }
    foreach ($bin in $Global:AuditConfig.Suspicious.LolBins) {
        if ($lower.Contains($bin.ToLowerInvariant())) { $signals += "LOLBin:$bin" }
    }
    foreach ($token in $Global:AuditConfig.Suspicious.CrackIndicators) {
        if ($lower.Contains($token)) { $signals += "CrackIndicator:$token" }
    }
    if (Test-SuspiciousPath -Path $CommandLine) { $signals += "UserWritablePath" }
    return @($signals | Select-Object -Unique)
}

function Get-RiskFromSignals {
    param(
        [array]$Signals,
        [string]$SignatureStatus = "Unknown",
        [bool]$MicrosoftTrusted = $false
    )
    if ($Signals -match "CrackIndicator|EncodedCommand|-encodedcommand|frombase64string") { return "CRITICAL" }
    if ($Signals -match "WMIPersistence|EncodedPowerShell|KnownSuspiciousProcess") { return "CRITICAL" }
    if ($Signals -match "LOLBin|ScriptToken|UnsignedInUserWritablePath|TempOrUserWritableExecution") { return "HIGH" }
    if (($Signals -match "UserWritablePath") -and -not $MicrosoftTrusted -and $SignatureStatus -ne "Valid") { return "HIGH" }
    if (($Signals -match "UserWritablePath") -and -not $MicrosoftTrusted) { return "WARNING" }
    if ($SignatureStatus -and $SignatureStatus -notin @("Valid", "Unknown")) { return "WARNING" }
    return "INFO"
}

function Get-SystemInfoMap {
    $map = @{}
    $lines = Invoke-SafeCommand { systeminfo.exe /FO LIST } @()
    foreach ($line in @($lines)) {
        if ($line -match "^(.*?):\s*(.*)$") {
            $map[$matches[1].Trim()] = $matches[2].Trim()
        }
    }
    return $map
}

function New-Recommendation {
    param(
        [Parameter(Mandatory)][string]$Issue,
        [ValidateSet("SAFE", "WARNING", "HIGH", "CRITICAL", "INFO")]
        [string]$Severity,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][string]$Impact,
        [Parameter(Mandatory)][string]$Recommendation,
        [string]$Fix = ""
    )

    return [ordered]@{
        issue = $Issue
        severity = $Severity
        description = $Description
        impact = $Impact
        recommendation = $Recommendation
        fix = $Fix
    }
}

function ConvertTo-SafeHtmlJson {
    param([Parameter(Mandatory)][string]$Json)
    return $Json.Replace("</script>", "<\/script>").Replace("<!--", "\u003c!--")
}

function Read-RegistryValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [object]$Default = $null
    )

    try {
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    } catch {
        return $Default
    }
}
