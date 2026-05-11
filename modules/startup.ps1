function Get-StartupPersistence {
    $recs = @()
    $entries = @()
    $scheduledTasks = @()
    $wmiPersistence = @()
    $browserPersistence = @()
    $runKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    foreach ($key in $runKeys) {
        $props = Invoke-SafeCommand { Get-ItemProperty -LiteralPath $key -ErrorAction Stop } $null
        if ($props) {
            foreach ($prop in $props.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" }) {
                $value = [string]$prop.Value
                $exe = Get-ExecutablePathFromCommand -CommandLine $value
                $signals = Get-CommandRiskSignals -CommandLine $value
                $trust = Get-TrustProfile -Path $exe -Signals $signals
                $signature = $trust.signature
                $severity = Get-RiskFromSignals -Signals $signals -SignatureStatus $signature.status -MicrosoftTrusted $trust.microsoftTrusted
                if ((Test-SuspiciousPath -Path $value) -and $signature.isSigned -eq $false) { $severity = "HIGH"; $signals += "UnsignedAutorunInUserWritablePath" }
                $entries += [ordered]@{ type = "Registry Run"; name = $prop.Name; command = $value; location = $key; executable = $exe; signatureStatus = $signature.status; signer = $signature.signer; trustScore = $trust.score; microsoftTrusted = $trust.microsoftTrusted; severity = $severity; riskSignals = @($signals | Select-Object -Unique) }
                if ($severity -eq "WARNING") {
                    $recs += New-Recommendation -Issue "Suspicious Startup Location" -Severity WARNING -Description "$($prop.Name) launches from a user-writable or staging path." -Impact "User-writable startup paths are common persistence locations." -Recommendation "Validate publisher, hash, and business purpose before allowing startup execution." -Fix "Get-ItemProperty -LiteralPath '$key'"
                }
                if ($severity -eq "HIGH") {
                    $recs += New-Recommendation -Issue "High-Risk Registry Autorun" -Severity HIGH -Description "$($prop.Name) has startup signals: $(@($signals) -join ', ')." -Impact "Registry autoruns execute at logon and are common malware persistence." -Recommendation "Disable the autorun until the binary is verified." -Fix "Remove-ItemProperty -LiteralPath '$key' -Name '$($prop.Name)'"
                }
            }
        }
    }

    $startupFolders = @(
        [Environment]::GetFolderPath("Startup"),
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    foreach ($folder in $startupFolders) {
        $files = Invoke-SafeCommand { Get-ChildItem -LiteralPath $folder -Force -ErrorAction Stop } @()
        foreach ($file in @($files)) {
            $signature = Get-FileSignatureInfo -Path $file.FullName
            $signals = Get-CommandRiskSignals -CommandLine $file.FullName
            $severity = Get-RiskFromSignals -Signals $signals -SignatureStatus $signature.status
            $entries += [ordered]@{ type = "Startup Folder"; name = $file.Name; command = $file.FullName; location = $folder; executable = $file.FullName; signatureStatus = $signature.status; signer = $signature.signer; severity = $severity; riskSignals = @($signals | Select-Object -Unique) }
        }
    }

    $specialPersistence = @(
        @{ type = "Winlogon"; path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; names = @("Shell", "Userinit") },
        @{ type = "AppInit_DLLs"; path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"; names = @("AppInit_DLLs", "LoadAppInit_DLLs") }
    )
    foreach ($target in $specialPersistence) {
        foreach ($name in $target.names) {
            $value = [string](Read-RegistryValue -Path $target.path -Name $name -Default "")
            if (-not [string]::IsNullOrWhiteSpace($value)) {
                $isDefaultWinlogon = ($target.type -eq "Winlogon" -and (($name -eq "Shell" -and $value -eq "explorer.exe") -or ($name -eq "Userinit" -and $value -like "*userinit.exe,*")))
                $signals = Get-CommandRiskSignals -CommandLine $value
                if (-not $isDefaultWinlogon) { $signals += "$($target.type)Persistence" }
                $severity = if ($isDefaultWinlogon) { "INFO" } else { "HIGH" }
                $row = [ordered]@{ type = $target.type; name = $name; command = $value; location = $target.path; executable = Get-ExecutablePathFromCommand -CommandLine $value; signatureStatus = "RegistryValue"; signer = ""; severity = $severity; riskSignals = @($signals | Select-Object -Unique) }
                $entries += $row
                if (-not $isDefaultWinlogon) {
                    $recs += New-Recommendation -Issue "$($target.type) Persistence Modification" -Severity HIGH -Description "$name contains non-default persistence value: $value." -Impact "This location can execute code during logon or process initialization." -Recommendation "Validate the registry value and restore enterprise baseline if unauthorized." -Fix "Get-ItemProperty -LiteralPath '$($target.path)'"
                }
            }
        }
    }

    $ifeo = Invoke-SafeCommand {
        Get-ChildItem -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -ErrorAction Stop |
            ForEach-Object {
                $debugger = Read-RegistryValue -Path $_.PsPath -Name "Debugger" -Default ""
                if ($debugger) { [pscustomobject]@{ Name = $_.PSChildName; Debugger = $debugger; Path = $_.PsPath } }
            }
    } @()
    foreach ($item in @($ifeo)) {
        $signals = Get-CommandRiskSignals -CommandLine $item.Debugger
        $signals += "IFEODebuggerHijack"
        $row = [ordered]@{ type = "IFEO Debugger"; name = $item.Name; command = $item.Debugger; location = $item.Path; executable = Get-ExecutablePathFromCommand -CommandLine $item.Debugger; signatureStatus = "RegistryValue"; signer = ""; severity = "CRITICAL"; riskSignals = @($signals | Select-Object -Unique) }
        $entries += $row
        $recs += New-Recommendation -Issue "IFEO Debugger Hijack" -Severity CRITICAL -Description "$($item.Name) has an Image File Execution Options debugger configured." -Impact "IFEO debugger values can hijack process launch and provide stealth persistence." -Recommendation "Remove unauthorized debugger values and investigate the referenced executable." -Fix "Remove-ItemProperty -LiteralPath '$($item.Path)' -Name Debugger"
    }

    $tasks = Invoke-SafeCommand {
        Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" } | Select-Object -First 300 TaskName, TaskPath, State, Author, Actions, Triggers, Settings
    } @()
    foreach ($task in @($tasks)) {
        $actionText = ($task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join "; "
        $triggerText = ($task.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ", "
        $signals = Get-CommandRiskSignals -CommandLine "$actionText $triggerText"
        $isHidden = [bool]$task.Settings.Hidden
        $isLogonOrBoot = $triggerText -match "Logon|Boot|Startup"
        if ($isHidden) { $signals += "HiddenTask" }
        if ($isLogonOrBoot) { $signals += "BootOrLogonTrigger" }
        $exe = Get-ExecutablePathFromCommand -CommandLine $actionText
        $signature = Get-FileSignatureInfo -Path $exe
        $severity = Get-RiskFromSignals -Signals $signals -SignatureStatus $signature.status
        if ($isHidden -and $severity -eq "INFO") { $severity = "WARNING" }
        $taskRow = [ordered]@{ type = "Scheduled Task"; name = $task.TaskName; command = $actionText; location = $task.TaskPath; triggers = $triggerText; hidden = $isHidden; executable = $exe; signatureStatus = $signature.status; signer = $signature.signer; severity = $severity; riskSignals = @($signals | Select-Object -Unique) }
        $scheduledTasks += $taskRow
        $entries += $taskRow
        if ($severity -in @("HIGH", "CRITICAL")) {
            $recs += New-Recommendation -Issue "Suspicious Scheduled Task" -Severity HIGH -Description "$($task.TaskName) contains suspicious script execution tokens." -Impact "Scheduled tasks are frequently used for malware persistence." -Recommendation "Inspect task action, principal, trigger, and file hash." -Fix "Get-ScheduledTask -TaskName '$($task.TaskName)' | Format-List *"
        }
    }

    $wmiFilters = Invoke-SafeCommand { Get-CimInstance -Namespace root/subscription -ClassName __EventFilter } @()
    foreach ($filter in @($wmiFilters)) {
        $row = [ordered]@{ type = "WMI Event Filter"; name = $filter.Name; command = $filter.Query; location = "root/subscription"; severity = "CRITICAL"; riskSignals = @("WMIPersistence") }
        $wmiPersistence += $row
        $entries += $row
    }
    $wmiConsumers = Invoke-SafeCommand { Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer } @()
    foreach ($consumer in @($wmiConsumers)) {
        $cmd = [string](Get-ObjectProperty -InputObject $consumer -Name "CommandLineTemplate" -Default (Get-ObjectProperty -InputObject $consumer -Name "ExecutablePath" -Default ""))
        $row = [ordered]@{ type = "WMI Event Consumer"; name = $consumer.Name; command = $cmd; location = "root/subscription"; severity = "CRITICAL"; riskSignals = @("WMIPersistence") }
        $wmiPersistence += $row
        $entries += $row
    }
    $wmiBindings = Invoke-SafeCommand {
        Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding
    } @()
    foreach ($binding in @($wmiBindings)) {
        $row = [ordered]@{ type = "WMI Binding"; name = $binding.PSComputerName; command = [string]$binding.Consumer; location = "root/subscription"; severity = "CRITICAL"; riskSignals = @("WMIPersistence") }
        $wmiPersistence += $row
        $entries += $row
        $recs += New-Recommendation -Issue "WMI Event Subscription Present" -Severity CRITICAL -Description "A permanent WMI event subscription exists." -Impact "WMI subscriptions can provide stealthy persistence that survives reboot and avoids common autorun checks." -Recommendation "Validate the filter and consumer, then remove unauthorized subscriptions." -Fix "Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding"
    }

    foreach ($policyPath in @("HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist", "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist", "HKCU:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist", "HKCU:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist")) {
        $props = Invoke-SafeCommand { Get-ItemProperty -LiteralPath $policyPath -ErrorAction Stop } $null
        if ($props) {
            foreach ($prop in $props.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" }) {
                $row = [ordered]@{ type = "Browser Forced Extension"; name = $prop.Name; command = [string]$prop.Value; location = $policyPath; severity = "HIGH"; riskSignals = @("ForcedBrowserExtension") }
                $browserPersistence += $row
                $entries += $row
                $recs += New-Recommendation -Issue "Policy-Forced Browser Extension" -Severity HIGH -Description "Browser extension $($prop.Value) is force-installed by policy." -Impact "Policy-installed extensions load persistently and may access browser data." -Recommendation "Validate the extension ID and policy source." -Fix "Get-ItemProperty -LiteralPath '$policyPath'"
            }
        }
    }

    return [ordered]@{
        entries = @($entries | Sort-Object @{ Expression = { Get-SeverityWeight $_.severity }; Descending = $true }, type, name)
        scheduledTasks = $scheduledTasks
        wmiPersistence = $wmiPersistence
        browserPersistence = $browserPersistence
        recommendations = $recs
    }
}
