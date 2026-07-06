param(
    [Parameter(Mandatory = $true)]
    [string]$CsvPath,

    [string]$Label = "",

    [int]$Limit = 0,

    [int]$DelayMs = 300,

    [switch]$WhatIfOnly,

    [switch]$IUnderstandThisIsALab
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $IUnderstandThisIsALab) {
    throw "Refusing to run. Re-run with -IUnderstandThisIsALab inside an isolated Windows lab VM."
}

if (-not (Test-Path -LiteralPath $CsvPath)) {
    throw "CSV file not found: $CsvPath"
}

$allowedSafetyClasses = @(
    "benign_safe_execution",
    "inert_string_telemetry",
    "safe_decode_only"
)

$rows = Import-Csv -LiteralPath $CsvPath

if ($Label -ne "") {
    $rows = $rows | Where-Object { $_.label -eq $Label }
}

if ($Limit -gt 0) {
    $rows = $rows | Select-Object -First $Limit
}

Write-Host "Loaded $($rows.Count) sample(s) from $CsvPath"
Write-Host "WhatIfOnly: $WhatIfOnly"

$index = 0
foreach ($row in $rows) {
    $index += 1

    if ($allowedSafetyClasses -notcontains $row.safety_class) {
        Write-Warning "Skipping $($row.id): safety class '$($row.safety_class)' is not allowed."
        continue
    }

    Write-Host ("[{0}/{1}] {2} {3} {4}" -f $index, $rows.Count, $row.id, $row.label, $row.scenario)

    if ($WhatIfOnly) {
        Write-Output $row.scriptblock
        continue
    }

    try {
        $scriptBlock = [ScriptBlock]::Create($row.scriptblock)
        & $scriptBlock | Out-Null
    }
    catch {
        Write-Warning "Sample $($row.id) failed: $($_.Exception.Message)"
    }

    if ($DelayMs -gt 0) {
        Start-Sleep -Milliseconds $DelayMs
    }
}

Write-Host "Done. Check Windows PowerShell ScriptBlock logs and Wazuh alerts for WAZUH_SAMPLE markers."
