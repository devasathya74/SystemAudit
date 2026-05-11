$Global:AuditConfig = @{
    Risk = @{
        SafeMax = 25
        WarningMax = 50
        HighMax = 75
        Weights = @{
            CRITICAL = 30
            HIGH = 18
            WARNING = 8
            SAFE = 0
            INFO = 0
        }
    }
    Ports = @{
        "21" = @{ severity = "HIGH"; service = "FTP"; impact = "Plaintext credential exposure and legacy file transfer risk"; fix = "Disable FTP service or restrict it behind VPN/firewall rules." }
        "23" = @{ severity = "CRITICAL"; service = "Telnet"; impact = "Plaintext remote shell access"; fix = "Disable Telnet and replace it with SSH over hardened access controls." }
        "445" = @{ severity = "HIGH"; service = "SMB"; impact = "Common lateral movement and ransomware exposure path"; fix = "Block inbound SMB from untrusted networks." }
        "3389" = @{ severity = "HIGH"; service = "RDP"; impact = "Remote desktop brute-force and exploitation exposure"; fix = "Disable RDP or require VPN, NLA, MFA, and allow-listing." }
        "5985" = @{ severity = "WARNING"; service = "WinRM HTTP"; impact = "Remote management endpoint exposed over HTTP"; fix = "Restrict WinRM to trusted hosts and prefer HTTPS." }
        "5986" = @{ severity = "WARNING"; service = "WinRM HTTPS"; impact = "Remote management endpoint requires tight access control"; fix = "Allow-list management sources and monitor authentication failures." }
    }
    Suspicious = @{
        ProcessNames = @("xmrig", "mimikatz", "procdump", "psexec", "nc", "netcat", "rclone", "anydesk")
        ScriptTokens = @("-enc", "-encodedcommand", "frombase64string", "downloadstring", "invoke-expression", "iex ", "bypass", "hidden", "nop", "w hidden")
        StartupPaths = @("\AppData\Roaming\", "\AppData\Local\Temp\", "\ProgramData\", "\Users\Public\")
        CrackIndicators = @("crack", "keygen", "kms", "activator", "patcher", "loader", "serial")
        LolBins = @("powershell.exe", "pwsh.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe", "wscript.exe", "cscript.exe", "wmic.exe", "certutil.exe", "bitsadmin.exe", "installutil.exe", "msbuild.exe", "forfiles.exe")
        BrowserExtensionKeywords = @("wallet", "crypto", "coupon", "search", "download", "pdf", "vpn", "proxy", "cleaner")
        VulnerableDriverKeywords = @("gdrv", "asrdrv", "rtcore", "dbutil", "inpout", "winring", "ene", "cpuz", "zamguard", "asupio")
    }
    Paths = @{}
}

function Initialize-AuditEnvironment {
    param([Parameter(Mandatory)][string]$RootPath)

    $Global:AuditConfig.Paths = @{
        Root = $RootPath
        Reports = Join-Path $RootPath "reports"
        Logs = Join-Path $RootPath "logs"
        Assets = Join-Path $RootPath "assets"
    }

    foreach ($path in $Global:AuditConfig.Paths.Values) {
        if (-not (Test-Path -LiteralPath $path)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
        }
    }
}
