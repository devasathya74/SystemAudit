function Get-CpuHealth {
    $recs = @()
    $cpu = Invoke-SafeCommand { Get-CimInstance Win32_Processor | Select-Object -First 1 } @{}
    $perf = Invoke-SafeCommand { Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'" } @{}
    $top = Invoke-SafeCommand {
        Get-Process | Sort-Object @{ Expression = { if ($_.CPU -is [TimeSpan]) { $_.CPU.TotalSeconds } else { $_.CPU } }; Descending = $true } | Select-Object -First 8 Name, Id, CPU, WorkingSet64
    } @()
    $temperature = Invoke-SafeCommand {
        $raw = Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature | Select-Object -First 1
        if ($raw.CurrentTemperature) { [math]::Round(($raw.CurrentTemperature / 10) - 273.15, 1) } else { $null }
    } $null

    $usage = [int](Get-ValueOrDefault -Value (Get-ValueOrDefault -Value (Get-ObjectProperty -InputObject $perf -Name "PercentProcessorTime") -Default (Get-ObjectProperty -InputObject $cpu -Name "LoadPercentage")) -Default 0)
    if ($usage -gt 95) {
        $recs += New-Recommendation -Issue "CPU Usage Above 95%" -Severity WARNING -Description "Processor utilization is critically high during collection." -Impact "Sustained load can degrade responsiveness and hide malicious workloads." -Recommendation "Review top CPU processes and baseline legitimate workload." -Fix "Get-Process | Sort-Object CPU -Descending | Select-Object -First 10"
    }
    if ($temperature -ne $null -and $temperature -gt 90) {
        $recs += New-Recommendation -Issue "CPU Temperature Above 90C" -Severity HIGH -Description "CPU thermal reading indicates possible overheating." -Impact "Thermal stress can cause throttling, shutdowns, or hardware degradation." -Recommendation "Inspect cooling, airflow, firmware fan curves, and sustained workload." -Fix ""
    }

    return [ordered]@{
        model = $cpu.Name
        usagePercent = $usage
        averageLoad = $cpu.LoadPercentage
        clockMHz = $cpu.CurrentClockSpeed
        maxClockMHz = $cpu.MaxClockSpeed
        cores = $cpu.NumberOfCores
        threads = $cpu.NumberOfLogicalProcessors
        temperatureC = $temperature
        topProcesses = @($top | ForEach-Object { @{ name = $_.Name; pid = $_.Id; cpu = [math]::Round((Get-ValueOrDefault -Value $_.CPU -Default 0), 2); memory = Convert-Bytes $_.WorkingSet64 } })
        recommendations = $recs
    }
}
