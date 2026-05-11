function Get-SystemAuditInfo {
    $systemInfo = Get-SystemInfoMap
    $cs = Invoke-SafeCommand { Get-CimInstance Win32_ComputerSystem } @{}
    $os = Invoke-SafeCommand { Get-CimInstance Win32_OperatingSystem } @{}
    $bios = Invoke-SafeCommand { Get-CimInstance Win32_BIOS } @{}
    $board = Invoke-SafeCommand { Get-CimInstance Win32_BaseBoard } @{}
    $cpu = Invoke-SafeCommand { Get-CimInstance Win32_Processor | Select-Object -First 1 } @{}
    $gpu = Invoke-SafeCommand { Get-CimInstance Win32_VideoController | Select-Object -First 1 } @{}
    $cpuRegistry = Read-RegistryValue -Path "HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0" -Name "ProcessorNameString" -Default $null
    $computerInfo = Invoke-SafeCommand { Get-ComputerInfo } $null
    $visualBasicMemory = Invoke-SafeCommand {
        Add-Type -AssemblyName Microsoft.VisualBasic
        (New-Object Microsoft.VisualBasic.Devices.ComputerInfo).TotalPhysicalMemory
    } $null
    $secureBoot = Invoke-SafeCommand { Confirm-SecureBootUEFI } $null
    $tpm = Invoke-SafeCommand { Get-Tpm } $null
    $uptime = if ($os.LastBootUpTime) { (Get-Date) - $os.LastBootUpTime } else { $null }
    if (-not $uptime -and $systemInfo.ContainsKey("System Boot Time")) {
        $boot = Invoke-SafeCommand { [datetime]::Parse($systemInfo["System Boot Time"]) } $null
        if ($boot) { $uptime = (Get-Date) - $boot }
    }
    $ramBytes = Get-ValueOrDefault -Value $cs.TotalPhysicalMemory -Default $visualBasicMemory

    return [ordered]@{
        hostname = $env:COMPUTERNAME
        username = "$env:USERDOMAIN\$env:USERNAME"
        domain = (Get-ValueOrDefault -Value $cs.Domain -Default $env:USERDOMAIN)
        os = (Get-ValueOrDefault -Value $os.Caption -Default (Get-ValueOrDefault -Value $systemInfo["OS Name"] -Default $computerInfo.WindowsProductName))
        osVersion = (Get-ValueOrDefault -Value $os.Version -Default (Get-ValueOrDefault -Value $systemInfo["OS Version"] -Default $computerInfo.OsVersion))
        buildNumber = (Get-ValueOrDefault -Value $os.BuildNumber -Default $computerInfo.OsBuildNumber)
        bios = (Get-ValueOrDefault -Value $bios.SMBIOSBIOSVersion -Default $systemInfo["BIOS Version"])
        motherboard = (Get-ValueOrDefault -Value (($board.Manufacturer, $board.Product) -join " ").Trim() -Default $systemInfo["System Model"])
        cpuModel = (Get-ValueOrDefault -Value $cpu.Name -Default $cpuRegistry)
        gpuModel = (Get-ValueOrDefault -Value $gpu.Name -Default "Unavailable without graphics WMI access")
        installedRam = Convert-Bytes $ramBytes
        uptime = if ($uptime) { "{0}d {1}h {2}m" -f $uptime.Days, $uptime.Hours, $uptime.Minutes } else { "Unknown" }
        secureBoot = $secureBoot
        tpm = if ($tpm) { @{ present = $tpm.TpmPresent; ready = $tpm.TpmReady; enabled = $tpm.TpmEnabled } } else { @{ present = $null; ready = $null; enabled = $null } }
        architecture = (Get-ValueOrDefault -Value $os.OSArchitecture -Default (Get-ValueOrDefault -Value $systemInfo["System Type"] -Default $env:PROCESSOR_ARCHITECTURE))
        bootMode = if ($secureBoot -ne $null) { "UEFI" } else { "Unknown" }
        collectionQuality = @{
            cimAvailable = [bool]$os.Caption
            fallbackUsed = -not [bool]$os.Caption
            source = if ($os.Caption) { "CIM" } else { "systeminfo/registry/.NET fallback" }
        }
        recommendations = @()
    }
}
