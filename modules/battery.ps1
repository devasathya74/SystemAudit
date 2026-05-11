function Get-BatteryHealth {
    $recs = @()
    $battery = Invoke-SafeCommand { Get-CimInstance Win32_Battery | Select-Object -First 1 } $null
    $static = Invoke-SafeCommand { Get-CimInstance -Namespace root/wmi -ClassName BatteryStaticData | Select-Object -First 1 } $null
    $full = Invoke-SafeCommand { Get-CimInstance -Namespace root/wmi -ClassName BatteryFullChargedCapacity | Select-Object -First 1 } $null
    if (-not $battery) {
        return @{ present = $false; recommendations = @() }
    }

    $design = [double](Get-ValueOrDefault -Value $static.DesignedCapacity -Default 0)
    $fullCharge = [double](Get-ValueOrDefault -Value $full.FullChargedCapacity -Default 0)
    $wear = if ($design -gt 0 -and $fullCharge -gt 0) { [math]::Round((1 - ($fullCharge / $design)) * 100, 2) } else { $null }
    if ($wear -ne $null -and $wear -gt 35) {
        $recs += New-Recommendation -Issue "Battery Wear Above 35%" -Severity WARNING -Description "Battery full charge capacity is substantially below design capacity." -Impact "Reduced runtime may affect mobile operations and field response work." -Recommendation "Plan battery replacement if this device is operationally important." -Fix ""
    }

    return [ordered]@{
        present = $true
        status = $battery.Status
        estimatedChargeRemaining = $battery.EstimatedChargeRemaining
        designCapacity = $design
        fullChargeCapacity = $fullCharge
        wearPercent = $wear
        cycleCount = $static.CycleCount
        health = if ($wear -eq $null) { "Unknown" } elseif ($wear -gt 35) { "Degraded" } else { "Healthy" }
        recommendations = $recs
    }
}
