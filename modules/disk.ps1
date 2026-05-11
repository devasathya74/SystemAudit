function Get-DiskHealth {
    $recs = @()
    $physical = Invoke-SafeCommand { Get-PhysicalDisk | Select-Object FriendlyName, MediaType, HealthStatus, OperationalStatus, Size } @()
    $volumes = Invoke-SafeCommand { Get-Volume | Where-Object DriveLetter | Select-Object DriveLetter, FileSystemLabel, FileSystem, HealthStatus, Size, SizeRemaining } @()
    $wmic = Invoke-SafeCommand { Get-CimInstance Win32_DiskDrive | Select-Object Model, Status, Size, InterfaceType } @()
    if (@($wmic).Count -eq 0) {
        $wmic = Invoke-SafeCommand {
            wmic diskdrive get Model,Status,Size,InterfaceType /format:csv |
                ConvertFrom-Csv |
                Where-Object { $_.Model } |
                Select-Object Model, Status, Size, InterfaceType
        } @()
    }
    if (@($volumes).Count -eq 0) {
        $volumes = Invoke-SafeCommand {
            Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Name -match "^[A-Z]$" } | ForEach-Object {
                [pscustomobject]@{
                    DriveLetter = $_.Name
                    FileSystemLabel = ""
                    FileSystem = "Unknown"
                    HealthStatus = "Unknown"
                    Size = ($_.Used + $_.Free)
                    SizeRemaining = $_.Free
                }
            }
        } @()
    }
    if (@($physical).Count -eq 0 -and @($wmic).Count -gt 0) {
        $physical = @($wmic | ForEach-Object {
            [pscustomobject]@{
                FriendlyName = $_.Model
                MediaType = $_.InterfaceType
                HealthStatus = if ($_.Status -eq "OK") { "Healthy" } else { $_.Status }
                OperationalStatus = $_.Status
                Size = $_.Size
            }
        })
    }

    foreach ($disk in @($physical)) {
        if ($disk.HealthStatus -and $disk.HealthStatus -ne "Healthy") {
            $recs += New-Recommendation -Issue "Disk Health Warning" -Severity HIGH -Description "$($disk.FriendlyName) reports health state $($disk.HealthStatus)." -Impact "Disk degradation can cause data loss or outage." -Recommendation "Back up critical data and run vendor diagnostics immediately." -Fix "Get-PhysicalDisk | Format-Table FriendlyName,HealthStatus,OperationalStatus"
        }
    }
    foreach ($vol in @($volumes)) {
        $freePercent = ConvertTo-Percent ([double](Get-ValueOrDefault -Value $vol.SizeRemaining -Default 0)) ([double](Get-ValueOrDefault -Value $vol.Size -Default 0))
        if ($freePercent -lt 10) {
            $recs += New-Recommendation -Issue "Low Disk Space on $($vol.DriveLetter):" -Severity WARNING -Description "Volume free space is below 10%." -Impact "Low storage can break updates, logging, paging, and application writes." -Recommendation "Free space or expand the volume before operational failure." -Fix "Get-Volume | Sort-Object SizeRemaining"
        }
        if ($freePercent -lt 5) {
            $recs += New-Recommendation -Issue "Critical Disk Space on $($vol.DriveLetter):" -Severity HIGH -Description "Volume free space is below 5%." -Impact "Critical storage pressure can cause application crashes, failed updates, and log loss." -Recommendation "Immediately free space, archive data, or extend the volume." -Fix "Get-PSDrive -PSProvider FileSystem"
        }
    }

    return [ordered]@{
        physicalDisks = @($physical | ForEach-Object { @{ name = $_.FriendlyName; type = $_.MediaType; health = $_.HealthStatus; operationalStatus = ($_.OperationalStatus -join ", "); size = Convert-Bytes $_.Size } })
        smart = @($wmic | ForEach-Object { @{ model = $_.Model; status = $_.Status; interface = $_.InterfaceType; size = Convert-Bytes $_.Size } })
        volumes = @($volumes | ForEach-Object { @{ drive = "$($_.DriveLetter):"; label = $_.FileSystemLabel; fileSystem = $_.FileSystem; health = $_.HealthStatus; size = Convert-Bytes $_.Size; free = Convert-Bytes $_.SizeRemaining; freePercent = ConvertTo-Percent $_.SizeRemaining $_.Size } })
        healthSummary = @{
            diskCount = @($physical).Count
            volumeCount = @($volumes).Count
            lowSpaceVolumes = @($volumes | Where-Object { (ConvertTo-Percent $_.SizeRemaining $_.Size) -lt 10 }).Count
            degradedDisks = @($physical | Where-Object { $_.HealthStatus -and $_.HealthStatus -notin @("Healthy", "OK") }).Count
            collectionSource = if (@($volumes).Count -gt 0) { "Get-Volume/Get-PSDrive fallback" } else { "Unavailable" }
        }
        recommendations = $recs
    }
}
