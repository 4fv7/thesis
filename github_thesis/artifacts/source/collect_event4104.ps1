param(
    [Parameter(Mandatory = $true)]
    [string]$DatasetPath,

    [Parameter(Mandatory = $true)]
    [string]$EventExportPath,

    [Parameter(Mandatory = $true)]
    [string]$SummaryPath,

    [Parameter(Mandatory = $true)]
    [string]$ReadyPath,

    [int]$TimeoutSeconds = 600,

    [int]$CompletionGraceSeconds = 8,

    [int]$PollMilliseconds = 250
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

$dataset = Get-Content -LiteralPath $DatasetPath -Raw | ConvertFrom-Json
$expectedIds = @(
    $dataset |
        ForEach-Object { ([string]$_.id).ToUpperInvariant() } |
        Sort-Object -Unique
)
if ($expectedIds.Count -eq 0) {
    throw "Dataset contains no sample IDs"
}

foreach ($path in @($EventExportPath, $SummaryPath, $ReadyPath)) {
    $parent = Split-Path -Parent $path
    if ($parent -ne "") {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
}
[System.IO.File]::WriteAllText(
    $EventExportPath,
    "",
    [System.Text.UTF8Encoding]::new($false)
)

$channel = "Microsoft-Windows-PowerShell/Operational"
$latest = Get-WinEvent -LogName $channel -MaxEvents 1
$lastRecordId = [long]$latest.RecordId
$startedAtUtc = (Get-Date).ToUniversalTime()
[ordered]@{
    ready_at_utc = $startedAtUtc.ToString("o")
    channel = $channel
    starting_record_id = $lastRecordId
    expected_sample_count = $expectedIds.Count
} | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $ReadyPath -Encoding UTF8

$assignmentPattern = '^\s*\$sampleId\s*=\s*([''"])(?<id>PST-\d{3})\1\s*;'
$markerPattern = ';\s*Write-(?:Output|Host)\s*\(\s*([''"])WAZUH_SAMPLE\s+\{0\}\1\s*-f\s*\$sampleId\s*\)\s*;?\s*$'
$idCounts = @{}
$invalidInstrumentation = [System.Collections.Generic.List[object]]::new()
$deadlineUtc = $startedAtUtc.AddSeconds($TimeoutSeconds)
$completeAtUtc = $null
$writer = [System.IO.StreamWriter]::new(
    $EventExportPath,
    $true,
    [System.Text.UTF8Encoding]::new($false)
)
$writer.AutoFlush = $true

try {
    while ((Get-Date).ToUniversalTime() -lt $deadlineUtc) {
        $xpath = "*[System[(EventID=4104) and (EventRecordID > $lastRecordId)]]"
        try {
            $events = @(
                Get-WinEvent -LogName $channel -FilterXPath $xpath -Oldest -ErrorAction Stop
            )
        }
        catch {
            $events = @()
        }

        foreach ($event in $events) {
            if ([long]$event.RecordId -gt $lastRecordId) {
                $lastRecordId = [long]$event.RecordId
            }
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
            $id = $assignment.Groups["id"].Value.ToUpperInvariant()
            if (-not $marker.Success -or $expectedIds -notcontains $id) {
                $invalidInstrumentation.Add([pscustomobject]@{
                    record_id = $event.RecordId
                    candidate_id = $id
                    terminal_marker_present = $marker.Success
                })
                continue
            }

            if (-not $idCounts.ContainsKey($id)) {
                $idCounts[$id] = 0
            }
            $idCounts[$id] += 1
            $record = [ordered]@{
                sample_id = $id
                channel = $channel
                provider_name = $event.ProviderName
                computer = $event.MachineName
                record_id = $event.RecordId
                time_created_utc = $event.TimeCreated.ToUniversalTime().ToString("o")
                event_id = $event.Id
                script_block_id = Get-EventDataValue -EventXml $eventXml -Name "ScriptBlockId"
                message_number = Get-EventDataValue -EventXml $eventXml -Name "MessageNumber"
                message_total = Get-EventDataValue -EventXml $eventXml -Name "MessageTotal"
                script_block_text = $scriptblockText
            }
            $writer.WriteLine(($record | ConvertTo-Json -Compress -Depth 5))
        }

        if ($idCounts.Count -eq $expectedIds.Count) {
            if ($null -eq $completeAtUtc) {
                $completeAtUtc = (Get-Date).ToUniversalTime()
            }
            elseif (
                ((Get-Date).ToUniversalTime() - $completeAtUtc).TotalSeconds -ge
                $CompletionGraceSeconds
            ) {
                break
            }
        }
        Start-Sleep -Milliseconds $PollMilliseconds
    }
}
finally {
    $writer.Dispose()
}

$missing = @($expectedIds | Where-Object { -not $idCounts.ContainsKey($_) })
$duplicates = [ordered]@{}
foreach ($id in ($idCounts.Keys | Sort-Object)) {
    if ($idCounts[$id] -gt 1) {
        $duplicates[$id] = $idCounts[$id]
    }
}
$hash = (
    Get-FileHash -Algorithm SHA256 -LiteralPath $EventExportPath
).Hash.ToLowerInvariant()
$summary = [ordered]@{
    started_at_utc = $startedAtUtc.ToString("o")
    finished_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    channel = $channel
    event_id = 4104
    starting_record_id = [long]$latest.RecordId
    ending_record_id = $lastRecordId
    expected_sample_count = $expectedIds.Count
    captured_record_count = ($idCounts.Values | Measure-Object -Sum).Sum
    unique_sample_count = $idCounts.Count
    missing_sample_ids = $missing
    duplicate_sample_ids = $duplicates
    invalid_instrumentation_records = $invalidInstrumentation
    event_export_path = $EventExportPath
    event_export_sha256 = $hash
}
$summary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $SummaryPath -Encoding UTF8
[ordered]@{
    expected_sample_count = $summary.expected_sample_count
    captured_record_count = $summary.captured_record_count
    unique_sample_count = $summary.unique_sample_count
    missing_sample_ids = $summary.missing_sample_ids
    duplicate_sample_ids = $summary.duplicate_sample_ids
    invalid_instrumentation_count = $invalidInstrumentation.Count
    event_export_sha256 = $summary.event_export_sha256
} | ConvertTo-Json -Depth 4

if (
    $missing.Count -gt 0 -or
    $duplicates.Count -gt 0 -or
    $invalidInstrumentation.Count -gt 0
) {
    throw "Live ScriptBlock capture validation failed"
}
