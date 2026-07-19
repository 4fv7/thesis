param(
    [Parameter(Mandatory = $true)]
    [string]$ExecutionLogPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath,

    [string]$EventExportPath = "",

    [int]$GraceSeconds = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-EventDataValue {
    param(
        [Parameter(Mandatory = $true)][xml]$EventXml,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $node = $EventXml.SelectSingleNode(
        "//*[local-name()='Data' and @Name='$Name']"
    )
    if ($null -eq $node) {
        return ""
    }
    return [string]$node.InnerText
}

$rows = @(Import-Csv -LiteralPath $ExecutionLogPath)
if ($rows.Count -eq 0) {
    throw "Execution log is empty: $ExecutionLogPath"
}

$expectedIds = @($rows.id | ForEach-Object { $_.ToUpperInvariant() } | Sort-Object -Unique)
$startUtc = ([datetime]$rows[0].start_utc).ToUniversalTime().AddSeconds(-$GraceSeconds)
$endUtc = ([datetime]$rows[-1].end_utc).ToUniversalTime().AddSeconds($GraceSeconds)
$startLocal = $startUtc.ToLocalTime()
$endLocal = $endUtc.ToLocalTime()
$events = @(Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-PowerShell/Operational"
    Id = 4104
    StartTime = $startLocal
    EndTime = $endLocal
})

$assignmentPattern = '^\s*\$sampleId\s*=\s*([''"])(?<id>PST-\d{3})\1\s*;'
$markerPattern = ';\s*Write-(?:Output|Host)\s*\(\s*([''"])WAZUH_SAMPLE\s+\{0\}\1\s*-f\s*\$sampleId\s*\)\s*;?\s*$'
$idCounts = @{}
$strictEventCount = 0
$invalidInstrumentationCount = 0
$eventRows = [System.Collections.Generic.List[object]]::new()

foreach ($event in $events) {
    [xml]$eventXml = $event.ToXml()
    $scriptblockText = Get-EventDataValue -EventXml $eventXml -Name "ScriptBlockText"
    $assignment = [regex]::Match(
        $scriptblockText,
        $assignmentPattern,
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
    if (-not $assignment.Success) {
        continue
    }

    $marker = [regex]::Match(
        $scriptblockText,
        $markerPattern,
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
            [System.Text.RegularExpressions.RegexOptions]::Singleline
    )
    if (-not $marker.Success) {
        $invalidInstrumentationCount += 1
        continue
    }

    $id = $assignment.Groups["id"].Value.ToUpperInvariant()
    if ($expectedIds -notcontains $id) {
        $invalidInstrumentationCount += 1
        continue
    }

    $strictEventCount += 1
    if (-not $idCounts.ContainsKey($id)) {
        $idCounts[$id] = 0
    }
    $idCounts[$id] += 1

    $eventRows.Add([pscustomobject]@{
        sample_id = $id
        record_id = $event.RecordId
        time_created_utc = $event.TimeCreated.ToUniversalTime().ToString("o")
        event_id = $event.Id
        script_block_id = Get-EventDataValue -EventXml $eventXml -Name "ScriptBlockId"
        message_number = Get-EventDataValue -EventXml $eventXml -Name "MessageNumber"
        message_total = Get-EventDataValue -EventXml $eventXml -Name "MessageTotal"
        script_block_text = $scriptblockText
    })
}

$missing = @($expectedIds | Where-Object { -not $idCounts.ContainsKey($_) })
$duplicates = [ordered]@{}
foreach ($id in ($idCounts.Keys | Sort-Object)) {
    if ($idCounts[$id] -gt 1) {
        $duplicates[$id] = $idCounts[$id]
    }
}

$eventExportSha256 = ""
if ($EventExportPath -ne "") {
    $parent = Split-Path -Parent $EventExportPath
    if ($parent -ne "") {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $jsonLines = @(
        $eventRows |
            Sort-Object sample_id, record_id |
            ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 5 }
    )
    [System.IO.File]::WriteAllLines(
        $EventExportPath,
        $jsonLines,
        [System.Text.UTF8Encoding]::new($false)
    )
    $eventExportSha256 = (
        Get-FileHash -Algorithm SHA256 -LiteralPath $EventExportPath
    ).Hash.ToLowerInvariant()
}

$summary = [ordered]@{
    verified_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    log_name = "Microsoft-Windows-PowerShell/Operational"
    event_id = 4104
    query_start_utc = $startUtc.ToString("o")
    query_end_utc = $endUtc.ToString("o")
    expected_sample_count = $expectedIds.Count
    strict_instrumentation_event_count = $strictEventCount
    unique_sample_count = $idCounts.Count
    invalid_instrumentation_event_count = $invalidInstrumentationCount
    missing_sample_ids = $missing
    duplicate_sample_ids = $duplicates
    full_event_export_path = $EventExportPath
    full_event_export_sha256 = $eventExportSha256
}

$summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
$summary | ConvertTo-Json -Depth 5

if (
    $missing.Count -gt 0 -or
    $duplicates.Count -gt 0 -or
    $invalidInstrumentationCount -gt 0
) {
    throw "ScriptBlock coverage validation failed"
}
