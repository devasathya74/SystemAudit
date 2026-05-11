function Get-UpdateAudit {
    $recs = @()
    $hotfixes = Invoke-SafeCommand { Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 HotFixID, Description, InstalledOn, InstalledBy } @()
    $latest = @($hotfixes | Select-Object -First 1)
    $days = if ($latest -and $latest[0].InstalledOn) { ((Get-Date) - [datetime]$latest[0].InstalledOn).Days } else { $null }
    if ($days -ne $null -and $days -gt 45) {
        $recs += New-Recommendation -Issue "Windows Updates Older Than 45 Days" -Severity WARNING -Description "Latest detected hotfix is $days days old." -Impact "Missing security updates increase exploitability." -Recommendation "Run Windows Update or enterprise patch deployment validation." -Fix "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10"
    }
    return @{ latestHotfixAgeDays = $days; recentHotfixes = @($hotfixes); recommendations = $recs }
}
