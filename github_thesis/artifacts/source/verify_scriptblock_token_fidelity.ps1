param(
    [Parameter(Mandatory = $true)]
    [string]$DatasetPath,

    [Parameter(Mandatory = $true)]
    [string]$MappedEventsCsvPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-TokenAnalysis {
    param([Parameter(Mandatory = $true)][string]$Text)

    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput(
        $Text,
        [ref]$tokens,
        [ref]$errors
    )
    $signature = @(
        $tokens |
            Where-Object {
                $_.Kind -notin @(
                    [System.Management.Automation.Language.TokenKind]::LineContinuation,
                    [System.Management.Automation.Language.TokenKind]::EndOfInput
                )
            } |
            ForEach-Object { "{0}|{1}" -f $_.Kind, $_.Text }
    )
    return [pscustomobject]@{
        parse_error_count = $errors.Count
        parse_errors = @($errors | ForEach-Object Message)
        statement_count = $ast.EndBlock.Statements.Count
        token_signature = $signature
    }
}

$dataset = Get-Content -LiteralPath $DatasetPath -Raw | ConvertFrom-Json
$mapped = @(Import-Csv -LiteralPath $MappedEventsCsvPath)
$mappedById = @{}
foreach ($row in $mapped) {
    if ($row.mapping_status -eq "mapped") {
        $mappedById[[string]$row.sample_id] = $row
    }
}

$lineContinuationPattern = (
    [regex]::Escape([string][char]96) + '(?:\r\n|\r|\n)'
)
$rows = [System.Collections.Generic.List[object]]::new()
foreach ($sample in $dataset) {
    $id = ([string]$sample.id).ToUpperInvariant()
    if (-not $mappedById.ContainsKey($id)) {
        $rows.Add([pscustomobject]@{
            sample_id = $id
            status = "missing_observed_text"
            expected_parse_errors = 0
            observed_parse_errors = 0
            token_sequences_equal = $false
        })
        continue
    }

    $expected = [string]$sample.scriptblock
    $observed = [string]$mappedById[$id].scriptblock_text
    if ($expected -ceq $observed) {
        $rows.Add([pscustomobject]@{
            sample_id = $id
            status = "exact"
            expected_parse_errors = 0
            observed_parse_errors = 0
            token_sequences_equal = $true
        })
        continue
    }

    $expectedAnalysis = Get-TokenAnalysis -Text $expected
    $observedAnalysis = Get-TokenAnalysis -Text $observed
    $expectedSignature = $expectedAnalysis.token_signature -join [Environment]::NewLine
    $observedSignature = $observedAnalysis.token_signature -join [Environment]::NewLine
    $tokenEqual = $expectedSignature -ceq $observedSignature
    $isLineContinuationRendering = (
        [regex]::IsMatch($expected, $lineContinuationPattern) -and
        $tokenEqual -and
        $expectedAnalysis.parse_error_count -eq 0 -and
        $observedAnalysis.parse_error_count -eq 0 -and
        $expectedAnalysis.statement_count -eq $observedAnalysis.statement_count
    )
    $status = if ($isLineContinuationRendering) {
        "token_equivalent_line_continuation_rendering"
    }
    elseif (
        $expectedAnalysis.parse_error_count -gt 0 -or
        $observedAnalysis.parse_error_count -gt 0
    ) {
        "parse_error"
    }
    else {
        "token_drift"
    }

    $rows.Add([pscustomobject]@{
        sample_id = $id
        status = $status
        expected_parse_errors = $expectedAnalysis.parse_error_count
        observed_parse_errors = $observedAnalysis.parse_error_count
        expected_statement_count = $expectedAnalysis.statement_count
        observed_statement_count = $observedAnalysis.statement_count
        token_sequences_equal = $tokenEqual
    })
}

$statusCounts = [ordered]@{}
foreach ($group in ($rows | Group-Object status | Sort-Object Name)) {
    $statusCounts[$group.Name] = $group.Count
}
$failures = @(
    $rows |
        Where-Object {
            $_.status -notin @(
                "exact",
                "token_equivalent_line_continuation_rendering"
            )
        }
)

$report = [ordered]@{
    checked_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    dataset_path = (Resolve-Path -LiteralPath $DatasetPath).Path
    mapped_events_csv_path = (Resolve-Path -LiteralPath $MappedEventsCsvPath).Path
    sample_count = $rows.Count
    status_counts = $statusCounts
    token_equivalent_line_continuation_ids = @(
        $rows |
            Where-Object status -eq "token_equivalent_line_continuation_rendering" |
            ForEach-Object sample_id
    )
    failure_ids = @($failures | ForEach-Object sample_id)
    records = @($rows | Where-Object status -ne "exact")
}

$parent = Split-Path -Parent $OutputPath
if ($parent -ne "") {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
}
$report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
[ordered]@{
    sample_count = $report.sample_count
    status_counts = $report.status_counts
    token_equivalent_line_continuation_ids = (
        $report.token_equivalent_line_continuation_ids
    )
    failure_ids = $report.failure_ids
} | ConvertTo-Json -Depth 4

if ($failures.Count -gt 0) {
    throw "ScriptBlock token-fidelity validation failed"
}
