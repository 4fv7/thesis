# Baseline Experiment: Standard Wazuh Rules

## Goal

Measure how Wazuh built-in rules react to a fixed set of 300 PowerShell
ScriptBlock samples before any custom rule enrichment is added.

## Sample distribution

| Group | Count |
|---|---:|
| Benign administrative samples | 100 |
| Clear simulated malicious indicator samples | 40 |
| Obfuscated simulated malicious variants | 160 |
| Total | 300 |

Obfuscation variants:

| Type | Count |
|---|---:|
| String concatenation | 40 |
| Mixed case | 40 |
| Safe Base64 literal decode | 40 |
| Backtick literal | 40 |

## Recommended execution order

1. Snapshot the Windows 11 lab VM.
2. Confirm ScriptBlock Logging is enabled.
3. Confirm Wazuh agent is connected and PowerShell Operational logs are forwarded.
4. Run all samples with standard Wazuh rules only.
5. Export Wazuh alerts.
6. Join alerts back to `id` values using the `WAZUH_SAMPLE <id>` marker.
7. Calculate TP, FP, TN, FN, Precision, Recall, F1-score, and False-Positive-Rate.

## Runner command

Run this from Windows PowerShell inside the isolated lab VM:

```powershell
.\tools\run_wazuh_samples.ps1 `
  -CsvPath .\data\powershell_scriptblock_samples.csv `
  -IUnderstandThisIsALab
```

Dry run:

```powershell
.\tools\run_wazuh_samples.ps1 `
  -CsvPath .\data\powershell_scriptblock_samples.csv `
  -IUnderstandThisIsALab `
  -WhatIfOnly `
  -Limit 5
```

## Important interpretation note

These samples are not live malware. They are telemetry-oriented test cases for
measuring rule behavior. A Wazuh alert on a simulated malicious sample means the
rule recognized an indicator in the ScriptBlock, not that a real attack was
successfully executed.
