function Get-EventLogAnalysis {
    $recs = @()
    $events = Invoke-SafeCommand {
        Get-WinEvent -FilterHashtable @{ LogName = "System"; Level = 1, 2; StartTime = (Get-Date).AddDays(-14) } -MaxEvents 80 |
            Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message
    } @()
    $summary = @($events | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object {
        @{ eventId = $_.Name; count = $_.Count; sample = ($_.Group[0].Message -replace "\s+", " ").Substring(0, [math]::Min(180, ($_.Group[0].Message -replace "\s+", " ").Length)) }
    })
    if (@($events).Count -gt 10) {
        $recs += New-Recommendation -Issue "Multiple Critical or Error System Events" -Severity WARNING -Description "$(@($events).Count) critical/error System log events were found in the last 14 days." -Impact "Repeated system errors may indicate instability, driver failures, or storage issues." -Recommendation "Review top event IDs and correlate with endpoint symptoms." -Fix "Get-WinEvent -FilterHashtable @{LogName='System';Level=1,2;StartTime=(Get-Date).AddDays(-14)} -MaxEvents 100"
    }
    return @{ events = @($events); summary = $summary; recommendations = $recs }
}
