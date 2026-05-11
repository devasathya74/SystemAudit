function Get-PortExposure {
    $recs = @()
    $tcp = Invoke-SafeCommand { Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess, State } @()
    $udp = Invoke-SafeCommand { Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess } @()
    if (@($tcp).Count -eq 0) {
        $tcp = Invoke-SafeCommand {
            netstat.exe -ano -p tcp | Select-String "LISTENING" | ForEach-Object {
                $parts = ($_.Line.Trim() -split "\s+")
                $endpoint = $parts[1]
                $portText = ($endpoint -split ":")[-1]
                $portNumber = 0
                if (-not [int]::TryParse($portText, [ref]$portNumber)) { return }
                [pscustomobject]@{
                    LocalAddress = ($endpoint -replace ":$portText$", "")
                    LocalPort = $portNumber
                    OwningProcess = [int]$parts[-1]
                    State = "Listen"
                }
            }
        } @()
    }
    if (@($udp).Count -eq 0) {
        $udp = Invoke-SafeCommand {
            netstat.exe -ano -p udp | Select-String "UDP" | ForEach-Object {
                $parts = ($_.Line.Trim() -split "\s+")
                $endpoint = $parts[1]
                $portText = ($endpoint -split ":")[-1]
                $portNumber = 0
                if (-not [int]::TryParse($portText, [ref]$portNumber)) { return }
                [pscustomobject]@{
                    LocalAddress = ($endpoint -replace ":$portText$", "")
                    LocalPort = $portNumber
                    OwningProcess = [int]$parts[-1]
                }
            }
        } @()
    }
    $processMap = @{}
    Invoke-SafeCommand { Get-Process | ForEach-Object { $processMap[[int]$_.Id] = $_.ProcessName } } | Out-Null

    $ports = @()
    foreach ($item in @($tcp)) {
        $port = [string]$item.LocalPort
        $classification = $Global:AuditConfig.Ports[$port]
        $severity = if ($classification) { $classification.severity } else { "INFO" }
        $processName = $processMap[[int]$item.OwningProcess]
        $ports += [ordered]@{ protocol = "TCP"; localAddress = $item.LocalAddress; port = [int]$item.LocalPort; pid = $item.OwningProcess; process = $processName; severity = $severity; service = if ($classification) { $classification.service } else { "" }; exposure = if ($item.LocalAddress -in @("0.0.0.0", "::", "[::]")) { "All interfaces" } else { "Scoped" } }
        if ($classification) {
            $recs += New-Recommendation -Issue "Exposed $($classification.service) Port $port" -Severity $classification.severity -Description "TCP port $port is listening on $($item.LocalAddress) by process $processName." -Impact $classification.impact -Recommendation $classification.fix -Fix "New-NetFirewallRule -DisplayName 'Block inbound port $port' -Direction Inbound -LocalPort $port -Protocol TCP -Action Block"
        }
    }
    foreach ($item in @($udp)) {
        $ports += [ordered]@{ protocol = "UDP"; localAddress = $item.LocalAddress; port = [int]$item.LocalPort; pid = $item.OwningProcess; process = $processMap[[int]$item.OwningProcess]; severity = "INFO"; service = ""; exposure = if ($item.LocalAddress -in @("0.0.0.0", "::", "[::]")) { "All interfaces" } else { "Scoped" } }
    }

    return [ordered]@{
        listeningPorts = @($ports | Sort-Object protocol, port)
        exposureSummary = @{
            tcpListening = @($ports | Where-Object protocol -eq "TCP").Count
            udpEndpoints = @($ports | Where-Object protocol -eq "UDP").Count
            highRisk = @($ports | Where-Object { $_.severity -in @("HIGH", "CRITICAL") }).Count
            allInterface = @($ports | Where-Object exposure -eq "All interfaces").Count
            collectionSource = if (@($tcp).Count -gt 0 -or @($udp).Count -gt 0) { "Get-NetTCPConnection/netstat fallback" } else { "Unavailable" }
        }
        recommendations = $recs
    }
}
