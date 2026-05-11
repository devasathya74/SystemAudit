function Get-NetworkAnalysis {
    param([switch]$IncludePublicIp)

    $adapters = Invoke-SafeCommand { Get-NetAdapter | Where-Object Status -eq Up | Select-Object Name, InterfaceDescription, MacAddress, LinkSpeed } @()
    $ipConfig = Invoke-SafeCommand { Get-NetIPConfiguration | Where-Object IPv4Address } @()
    $connections = Invoke-SafeCommand { Get-NetTCPConnection | Where-Object State -eq Established | Select-Object -First 100 LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess } @()
    $dnsTest = Invoke-SafeCommand { Resolve-DnsName "microsoft.com" -ErrorAction Stop | Select-Object -First 1 } $null
    $ping = Invoke-SafeCommand { Test-Connection -ComputerName "1.1.1.1" -Count 2 -ErrorAction Stop | Measure-Object ResponseTime -Average } $null
    $publicIp = if ($IncludePublicIp) { Invoke-SafeCommand { Invoke-RestMethod -Uri "https://api.ipify.org" -TimeoutSec 5 } "Skipped" } else { "Skipped" }

    return [ordered]@{
        adapters = @($adapters)
        dnsServers = @($ipConfig | ForEach-Object { $_.DNSServer.ServerAddresses } | Select-Object -Unique)
        gateways = @($ipConfig | ForEach-Object { $_.IPv4DefaultGateway.NextHop } | Where-Object { $_ } | Select-Object -Unique)
        publicIp = $publicIp
        latencyMs = if ($ping) { [math]::Round($ping.Average, 2) } else { $null }
        dnsResolution = [bool]$dnsTest
        activeConnections = @($connections)
        recommendations = @()
    }
}
