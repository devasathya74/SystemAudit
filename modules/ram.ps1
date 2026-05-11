function Get-RamAnalysis {
    $recs = @()
    $os = Invoke-SafeCommand { Get-CimInstance Win32_OperatingSystem } @{}
    $page = Invoke-SafeCommand { Get-CimInstance Win32_PageFileUsage | Select-Object -First 1 } @{}
    $vb = Invoke-SafeCommand {
        Add-Type -AssemblyName Microsoft.VisualBasic
        New-Object Microsoft.VisualBasic.Devices.ComputerInfo
    } $null
    $fallbackTotalKb = 0
    $fallbackFreeKb = 0
    if ($vb) {
        $fallbackTotalKb = [math]::Round($vb.TotalPhysicalMemory / 1KB, 0)
        $fallbackFreeKb = [math]::Round($vb.AvailablePhysicalMemory / 1KB, 0)
    }
    $totalKb = [double](Get-ValueOrDefault -Value $os.TotalVisibleMemorySize -Default $fallbackTotalKb)
    $freeKb = [double](Get-ValueOrDefault -Value $os.FreePhysicalMemory -Default $fallbackFreeKb)
    $usedKb = [math]::Max(0, $totalKb - $freeKb)
    $usedPercent = ConvertTo-Percent $usedKb $totalKb
    $pagePercent = ConvertTo-Percent ([double](Get-ValueOrDefault -Value $page.CurrentUsage -Default 0)) ([double](Get-ValueOrDefault -Value $page.AllocatedBaseSize -Default 0))

    if ($usedPercent -gt 90) {
        $recs += New-Recommendation -Issue "RAM Pressure Above 90%" -Severity WARNING -Description "Physical memory usage is near exhaustion." -Impact "High memory pressure can cause paging, application failures, and poor endpoint responsiveness." -Recommendation "Identify heavy consumers and consider capacity or workload changes." -Fix "Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 15"
    }
    if ($pagePercent -gt 75) {
        $recs += New-Recommendation -Issue "Excessive Pagefile Usage" -Severity WARNING -Description "Pagefile usage is elevated." -Impact "Heavy paging indicates insufficient RAM or memory leaks." -Recommendation "Review memory-heavy processes and pagefile sizing." -Fix ""
    }

    return [ordered]@{
        total = Convert-Bytes ($totalKb * 1KB)
        used = Convert-Bytes ($usedKb * 1KB)
        available = Convert-Bytes ($freeKb * 1KB)
        usedPercent = $usedPercent
        cached = "Unavailable"
        pagefileUsagePercent = $pagePercent
        memoryPressure = if ($usedPercent -gt 90) { "High" } elseif ($usedPercent -gt 75) { "Elevated" } else { "Normal" }
        collectionQuality = @{
            cimAvailable = [bool]$os.TotalVisibleMemorySize
            fallbackUsed = -not [bool]$os.TotalVisibleMemorySize
            source = if ($os.TotalVisibleMemorySize) { "CIM Win32_OperatingSystem" } else { ".NET ComputerInfo fallback" }
        }
        recommendations = $recs
    }
}
