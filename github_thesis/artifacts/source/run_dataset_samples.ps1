param(
    [Parameter(Mandatory = $true)]
    [string]$DatasetPath,

    [string]$Label = "",

    [string]$DatasetGroup = "",

    [int]$Limit = 0,

    [int]$DelayMs = 300,

    [string]$ExecutionLogPath = "",

    [switch]$WhatIfOnly,

    [switch]$PreflightOnly,

    [switch]$IUnderstandThisIsALab
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $IUnderstandThisIsALab) {
    throw "Refusing to run. Re-run with -IUnderstandThisIsALab inside the isolated Windows 11 laboratory environment."
}

if (-not (Test-Path -LiteralPath $DatasetPath)) {
    throw "Dataset file not found: $DatasetPath"
}

$allowedSafetyClasses = @(
    "benign_safe_execution",
    "simulated_malicious_non_executable",
    "simulated_malicious_non_executable_obfuscated"
)

$forbiddenCommands = @(
    "Invoke-Expression",
    "Invoke-WebRequest",
    "Invoke-RestMethod",
    "Start-BitsTransfer",
    "bitsadmin",
    "certutil",
    "mshta",
    "regsvr32",
    "rundll32",
    "Register-ScheduledTask",
    "New-ItemProperty",
    "Set-ItemProperty",
    "Set-MpPreference",
    "Add-MpPreference",
    "New-Service",
    "Start-Process",
    "Invoke-Command",
    "Enter-PSSession",
    "New-PSSession",
    "Remove-Item",
    "Set-Content",
    "Add-Content"
)

function Get-ScriptCommandNames {
    param([Parameter(Mandatory = $true)][string]$Text)

    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput(
        $Text,
        [ref]$tokens,
        [ref]$parseErrors
    )
    if ($parseErrors.Count -gt 0) {
        throw "PowerShell parser rejected sample: $($parseErrors[0].Message)"
    }

    $commands = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst]
    }, $true)

    return @(
        $commands |
            ForEach-Object { $_.GetCommandName() } |
            Where-Object { $_ } |
            Sort-Object -Unique
    )
}

function Test-SampleSafety {
    param([Parameter(Mandatory = $true)]$Row)

    $commandNames = @(Get-ScriptCommandNames -Text ([string]$Row.scriptblock))
    $forbidden = @($commandNames | Where-Object { $forbiddenCommands -contains $_ })
    if ($forbidden.Count -gt 0) {
        return [pscustomobject]@{
            Allowed = $false
            Reason = "forbidden command(s): $($forbidden -join ', ')"
            Commands = $commandNames -join ";"
        }
    }

    if ($Row.label -eq "simulated_malicious") {
        $unexpected = @($commandNames | Where-Object { $_ -ne "Write-Output" })
        if ($unexpected.Count -gt 0) {
            return [pscustomobject]@{
                Allowed = $false
                Reason = "positive sample invokes command(s) other than Write-Output: $($unexpected -join ', ')"
                Commands = $commandNames -join ";"
            }
        }
    }

    return [pscustomobject]@{
        Allowed = $true
        Reason = "static AST preflight passed"
        Commands = $commandNames -join ";"
    }
}

$rows = Get-Content -LiteralPath $DatasetPath -Raw | ConvertFrom-Json

if ($Label -ne "") {
    $rows = @($rows | Where-Object { $_.label -eq $Label })
}

if ($DatasetGroup -ne "") {
    $rows = @($rows | Where-Object { $_.dataset_group -eq $DatasetGroup })
}

if ($Limit -gt 0) {
    $rows = @($rows | Select-Object -First $Limit)
}

Write-Host "Loaded $($rows.Count) sample(s) from $DatasetPath"
Write-Host "WhatIfOnly: $WhatIfOnly"
Write-Host "PreflightOnly: $PreflightOnly"

if ($ExecutionLogPath -eq "") {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $ExecutionLogPath = Join-Path (Split-Path -Parent $DatasetPath) "execution_$timestamp.csv"
}

$executionRows = [System.Collections.Generic.List[object]]::new()
$executionLogInitialized = $false

try {
    [System.IO.File]::WriteAllText($ExecutionLogPath, "")
}
catch {
    throw "Execution log is not writable: $ExecutionLogPath ($($_.Exception.Message))"
}

function Add-ExecutionRow {
    param([Parameter(Mandatory = $true)][object]$Record)

    $executionRows.Add($Record)
    if ($script:executionLogInitialized) {
        $Record | Export-Csv -LiteralPath $ExecutionLogPath -NoTypeInformation -Encoding UTF8 -Append
    }
    else {
        $Record | Export-Csv -LiteralPath $ExecutionLogPath -NoTypeInformation -Encoding UTF8
        $script:executionLogInitialized = $true
    }
}

$index = 0
foreach ($row in $rows) {
    $index += 1

    if ($allowedSafetyClasses -notcontains $row.safety_class) {
        Write-Warning "Skipping $($row.id): safety class '$($row.safety_class)' is not allowed."
        Add-ExecutionRow ([pscustomobject]@{
            id = $row.id
            label = $row.label
            start_utc = (Get-Date).ToUniversalTime().ToString("o")
            end_utc = (Get-Date).ToUniversalTime().ToString("o")
            status = "skipped"
            reason = "safety class not allowed"
            commands = ""
        })
        continue
    }

    $preflight = Test-SampleSafety -Row $row
    if (-not $preflight.Allowed) {
        Write-Warning "Skipping $($row.id): $($preflight.Reason)"
        Add-ExecutionRow ([pscustomobject]@{
            id = $row.id
            label = $row.label
            start_utc = (Get-Date).ToUniversalTime().ToString("o")
            end_utc = (Get-Date).ToUniversalTime().ToString("o")
            status = "skipped"
            reason = $preflight.Reason
            commands = $preflight.Commands
        })
        continue
    }

    Write-Host ("[{0}/{1}] {2} {3} {4}" -f $index, $rows.Count, $row.id, $row.label, $row.scenario)

    if ($WhatIfOnly) {
        Write-Output $row.scriptblock
        continue
    }

    if ($PreflightOnly) {
        Add-ExecutionRow ([pscustomobject]@{
            id = $row.id
            label = $row.label
            start_utc = (Get-Date).ToUniversalTime().ToString("o")
            end_utc = (Get-Date).ToUniversalTime().ToString("o")
            status = "preflight_passed"
            reason = $preflight.Reason
            commands = $preflight.Commands
        })
        continue
    }

    $startUtc = (Get-Date).ToUniversalTime().ToString("o")
    try {
        $scriptBlock = [ScriptBlock]::Create([string]$row.scriptblock)
        & $scriptBlock | Out-Null
        $status = "executed"
        $reason = ""
    }
    catch {
        Write-Warning "Sample $($row.id) failed: $($_.Exception.Message)"
        $status = "failed"
        $reason = $_.Exception.Message
    }

    Add-ExecutionRow ([pscustomobject]@{
        id = $row.id
        label = $row.label
        start_utc = $startUtc
        end_utc = (Get-Date).ToUniversalTime().ToString("o")
        status = $status
        reason = $reason
        commands = $preflight.Commands
    })

    if ($DelayMs -gt 0) {
        Start-Sleep -Milliseconds $DelayMs
    }
}

Write-Host "Execution log: $ExecutionLogPath"
Write-Host "Done. Check Microsoft-Windows-PowerShell/Operational logs and Wazuh alerts for WAZUH_SAMPLE markers."
