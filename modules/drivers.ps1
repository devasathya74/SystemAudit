function Get-DriverIntelligence {
    $recs = @()
    $drivers = Invoke-SafeCommand {
        Get-CimInstance Win32_SystemDriver | Select-Object Name, DisplayName, State, StartMode, PathName, ServiceType
    } @()
    if (@($drivers).Count -eq 0) {
        $drivers = Invoke-SafeCommand {
            driverquery.exe /v /fo csv | ConvertFrom-Csv | ForEach-Object {
                [pscustomobject]@{
                    Name = $_."Module Name"
                    DisplayName = $_."Display Name"
                    State = $_.State
                    StartMode = $_."Start Mode"
                    PathName = $_."Path"
                    ServiceType = $_."Driver Type"
                }
            }
        } @()
    }
    if (@($drivers).Count -eq 0) {
        $drivers = Invoke-SafeCommand {
            Get-ChildItem -LiteralPath "$env:SystemRoot\System32\drivers" -Filter *.sys -File -ErrorAction Stop | Select-Object -First 500 | ForEach-Object {
                [pscustomobject]@{
                    Name = $_.BaseName
                    DisplayName = $_.Name
                    State = "Unknown"
                    StartMode = "Unknown"
                    PathName = $_.FullName
                    ServiceType = "Kernel Driver"
                }
            }
        } @()
    }
    $rows = @()
    foreach ($driver in @($drivers)) {
        $path = [string]$driver.PathName
        $normalized = $path -replace "\\SystemRoot", $env:SystemRoot
        $normalized = $normalized -replace "^\\\?\?\\", ""
        $exe = Get-ExecutablePathFromCommand -CommandLine $normalized
        $signature = Get-FileSignatureInfo -Path $exe
        $signals = Get-CommandRiskSignals -CommandLine "$($driver.Name) $path"
        foreach ($keyword in $Global:AuditConfig.Suspicious.VulnerableDriverKeywords) {
            if (([string]$driver.Name).ToLowerInvariant().Contains($keyword) -or $path.ToLowerInvariant().Contains($keyword)) {
                $signals += "VulnerableDriverKeyword:$keyword"
            }
        }
        if ($driver.State -eq "Stopped" -and $driver.StartMode -in @("Auto", "System", "Boot")) { $signals += "FailedOrStoppedBootDriver" }
        $severity = Get-RiskFromSignals -Signals $signals -SignatureStatus $signature.status
        if ($signature.isSigned -eq $false) { $severity = "HIGH" }
        if ($signals -match "VulnerableDriverKeyword") { $severity = "HIGH" }
        if ($driver.State -eq "Stopped" -and $driver.StartMode -in @("Auto", "System", "Boot") -and $severity -eq "INFO") { $severity = "WARNING" }
        $row = [ordered]@{
            name = $driver.Name
            displayName = $driver.DisplayName
            status = $driver.State
            startType = $driver.StartMode
            serviceType = $driver.ServiceType
            path = $path
            normalizedPath = $exe
            signatureStatus = $signature.status
            signer = $signature.signer
            signed = $signature.isSigned
            vendor = $signature.signer
            severity = $severity
            riskSignals = @($signals | Select-Object -Unique)
        }
        $rows += $row
        if ($signature.isSigned -eq $false) {
            $recs += New-Recommendation -Issue "Unsigned Driver Detected" -Severity HIGH -Description "$($driver.Name) driver binary is unsigned." -Impact "Unsigned kernel drivers can indicate rootkit risk or unstable low-level software." -Recommendation "Disable unauthorized drivers and validate vendor provenance." -Fix "sc.exe query `"$($driver.Name)`""
        } elseif ($signals -match "VulnerableDriverKeyword") {
            $recs += New-Recommendation -Issue "Potentially Vulnerable Driver" -Severity HIGH -Description "$($driver.Name) matches known vulnerable driver naming patterns." -Impact "Vulnerable signed drivers can be abused for privilege escalation or defense evasion." -Recommendation "Verify version against vendor advisories and remove outdated driver packages." -Fix "driverquery /v /fo csv"
        } elseif ($row.riskSignals -contains "FailedOrStoppedBootDriver") {
            $recs += New-Recommendation -Issue "Boot/System Driver Not Running" -Severity WARNING -Description "$($driver.Name) is configured for early/automatic load but is stopped." -Impact "Failed drivers can explain instability or missing hardware/security functionality." -Recommendation "Review System event logs and update or remove the driver." -Fix "Get-CimInstance Win32_SystemDriver -Filter `"Name='$($driver.Name)'`""
        }
    }
    return [ordered]@{
        drivers = @($rows | Sort-Object @{ Expression = { Get-SeverityWeight $_.severity }; Descending = $true }, name)
        unsignedDrivers = @($rows | Where-Object { $_.signed -eq $false })
        failedDrivers = @($rows | Where-Object { $_.riskSignals -contains "FailedOrStoppedBootDriver" })
        recommendations = $recs
    }
}
