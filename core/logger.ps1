$script:LogEntries = [System.Collections.Generic.List[object]]::new()
$script:LogFile = $null
$script:ConsoleEnabled = $true

function Initialize-Logger {
    param(
        [Parameter(Mandatory)][string]$LogDirectory,
        [bool]$ConsoleEnabled = $true
    )

    if (-not (Test-Path -LiteralPath $LogDirectory)) {
        New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
    }

    $script:ConsoleEnabled = $ConsoleEnabled
    $script:LogFile = Join-Path $LogDirectory ("audit-{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
    New-Item -ItemType File -Path $script:LogFile -Force | Out-Null
}

function Write-Log {
    param(
        [ValidateSet("INFO", "OK", "WARN", "ERROR", "DEBUG")]
        [string]$Level = "INFO",
        [Parameter(Mandatory)][string]$Message,
        [hashtable]$Data = @{}
    )

    $entry = [ordered]@{
        timestamp = (Get-Date).ToString("o")
        level = $Level
        message = $Message
        data = $Data
    }

    $script:LogEntries.Add($entry)
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    if ($script:LogFile) {
        try {
            [System.IO.File]::AppendAllText($script:LogFile, "$line$([Environment]::NewLine)", [System.Text.Encoding]::UTF8)
        } catch {
            $script:LogFile = $null
        }
    }
    if ($script:ConsoleEnabled) {
        Write-Host $line
    }
}

function Get-LogEntries {
    return @($script:LogEntries)
}
