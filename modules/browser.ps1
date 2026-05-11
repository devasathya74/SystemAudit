function Get-BrowserSecurity {
    $recs = @()
    $candidates = @(
        @{ name = "Chrome"; paths = @("$env:ProgramFiles\Google\Chrome\Application\chrome.exe", "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe") },
        @{ name = "Edge"; paths = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe") },
        @{ name = "Firefox"; paths = @("$env:ProgramFiles\Mozilla Firefox\firefox.exe", "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") }
    )
    $browsers = @()
    foreach ($candidate in $candidates) {
        foreach ($path in $candidate.paths) {
            if ($path -and (Test-Path -LiteralPath $path)) {
                $version = (Get-Item -LiteralPath $path).VersionInfo.ProductVersion
                $browsers += @{ name = $candidate.name; path = $path; version = $version }
                break
            }
        }
    }
    $extensionRoots = @(
        @{ browser = "Chrome"; path = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"; profile = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default" },
        @{ browser = "Edge"; path = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"; profile = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default" }
    )
    $extensions = @()
    $configs = @()
    foreach ($root in $extensionRoots) {
        $items = Invoke-SafeCommand { Get-ChildItem -LiteralPath $root.path -Directory -ErrorAction Stop } @()
        foreach ($item in @($items)) {
            $versions = Invoke-SafeCommand { Get-ChildItem -LiteralPath $item.FullName -Directory -ErrorAction Stop | Sort-Object Name -Descending } @()
            $versionDir = @($versions | Select-Object -First 1)[0]
            $manifestPath = if ($versionDir) { Join-Path $versionDir.FullName "manifest.json" } else { "" }
            $manifest = if ($manifestPath -and (Test-Path -LiteralPath $manifestPath)) { Invoke-SafeCommand { Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json } $null } else { $null }
            $name = if ($manifest) { [string]$manifest.name } else { $item.Name }
            $permissions = if ($manifest -and $manifest.permissions) { @($manifest.permissions) } else { @() }
            $hostPermissions = if ($manifest -and $manifest.host_permissions) { @($manifest.host_permissions) } else { @() }
            $signals = @()
            foreach ($keyword in $Global:AuditConfig.Suspicious.BrowserExtensionKeywords) {
                if (($name.ToLowerInvariant()).Contains($keyword)) { $signals += "ExtensionKeyword:$keyword" }
            }
            if (($permissions -join " ") -match "tabs|webRequest|cookies|nativeMessaging|management|debugger") { $signals += "SensitivePermission" }
            if (($hostPermissions -join " ") -match "<all_urls>|\*://\*/\*") { $signals += "AllUrlsAccess" }
            $severity = if ($signals -match "AllUrlsAccess|SensitivePermission") { "WARNING" } else { "INFO" }
            if ($signals -match "wallet|crypto") { $severity = "HIGH" }
            $extensions += [ordered]@{
                id = $item.Name
                name = $name
                version = if ($manifest) { $manifest.version } else { "" }
                browser = $root.browser
                path = $item.FullName
                permissions = $permissions
                hostPermissions = $hostPermissions
                severity = $severity
                riskSignals = @($signals | Select-Object -Unique)
            }
            if ($severity -in @("WARNING", "HIGH")) {
                $recs += New-Recommendation -Issue "Risky Browser Extension" -Severity $severity -Description "$name has sensitive permissions or suspicious extension keywords." -Impact "Browser extensions can read pages, credentials, cookies, and wallet/session data depending on permissions." -Recommendation "Validate extension source, permissions, and business need; remove unknown extensions." -Fix ""
            }
        }
        $prefPath = Join-Path $root.profile "Preferences"
        $prefs = if (Test-Path -LiteralPath $prefPath) { Invoke-SafeCommand { Get-Content -LiteralPath $prefPath -Raw | ConvertFrom-Json } $null } else { $null }
        if ($prefs) {
            $configs += [ordered]@{
                browser = $root.browser
                startupPages = @($prefs.session.startup_urls)
                restoreOnStartup = $prefs.session.restore_on_startup
                passwordManagerEnabled = $prefs.profile.password_manager_enabled
                unsafeFlags = @()
            }
        }
    }
    $policies = @()
    foreach ($policyPath in @("HKLM:\SOFTWARE\Policies\Google\Chrome", "HKLM:\SOFTWARE\Policies\Microsoft\Edge", "HKCU:\SOFTWARE\Policies\Google\Chrome", "HKCU:\SOFTWARE\Policies\Microsoft\Edge")) {
        $props = Invoke-SafeCommand { Get-ItemProperty -LiteralPath $policyPath -ErrorAction Stop } $null
        if ($props) {
            foreach ($prop in $props.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" }) {
                $policies += @{ path = $policyPath; name = $prop.Name; value = [string]$prop.Value }
            }
        }
    }
    $forced = @($policies | Where-Object { $_.name -match "ExtensionInstall|DeveloperTools|Password|SafeBrowsing|Homepage" })
    if ($forced.Count -gt 0) {
        $recs += New-Recommendation -Issue "Browser Security Policies Present" -Severity WARNING -Description "$($forced.Count) browser policy settings affect extensions or security configuration." -Impact "Policies can force extensions, alter safe browsing, or control startup/homepage behavior." -Recommendation "Validate policy source and intended configuration." -Fix ""
    }
    if ($extensions.Count -gt 25) {
        $recs += New-Recommendation -Issue "High Browser Extension Count" -Severity WARNING -Description "A large number of Chromium extensions were detected." -Impact "Extensions can access browsing data and become supply-chain risk." -Recommendation "Review installed extensions and remove anything untrusted or unused." -Fix ""
    }
    return @{ browsers = $browsers; extensions = $extensions; configs = $configs; policies = $policies; riskyExtensions = @($extensions | Where-Object { $_.severity -in @("WARNING", "HIGH", "CRITICAL") }); recommendations = $recs }
}
