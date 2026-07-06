# Full Experiment Setup

This document describes the practical workflow for the thesis experiment.

## 1. Lab Requirements

- Windows 11 lab VM or isolated host.
- PowerShell ScriptBlock Logging enabled.
- Wazuh agent installed on the Windows 11 system.
- Wazuh manager/dashboard running separately.
- Python 3.10+ on the analysis machine.
- Final dataset:

```text
C:\Users\alsoh\Downloads\powershell_scriptblock_dataset_final_thesis_v4_package\powershell_scriptblock_samples_final_thesis_v4.json
```

## 2. Wazuh Baseline Setup

1. Enable ScriptBlock Logging.
2. Configure the Wazuh agent to collect:

```text
Microsoft-Windows-PowerShell/Operational
```

3. Restart the Wazuh agent.
4. Confirm that event ID 4104 reaches Wazuh.
5. Keep Wazuh in standard-rule mode for the first experiment.

See `WAZUH_AGENT_POWERSHELL_CONFIG.md` for details.

## 3. Dry Run the Dataset Runner

Copy this folder and the dataset to the Windows 11 lab VM, or run from a shared
path accessible to Windows PowerShell.

Dry run:

```powershell
powershell.exe -ExecutionPolicy Bypass `
  -File .\thesis_wazuh_pipeline\tools\run_dataset_samples.ps1 `
  -DatasetPath "C:\Users\alsoh\Downloads\powershell_scriptblock_dataset_final_thesis_v4_package\powershell_scriptblock_samples_final_thesis_v4.json" `
  -IUnderstandThisIsALab `
  -WhatIfOnly `
  -Limit 5
```

## 4. Execute the Full Dataset

Inside the isolated Windows 11 lab VM:

```powershell
powershell.exe -ExecutionPolicy Bypass `
  -File .\thesis_wazuh_pipeline\tools\run_dataset_samples.ps1 `
  -DatasetPath "C:\Users\alsoh\Downloads\powershell_scriptblock_dataset_final_thesis_v4_package\powershell_scriptblock_samples_final_thesis_v4.json" `
  -IUnderstandThisIsALab `
  -DelayMs 300
```

Each sample writes a marker:

```text
WAZUH_SAMPLE <sample_id> <scenario>
```

The pipeline uses this marker to map Wazuh alerts back to dataset entries.

## 5. Export Wazuh Alerts

Preferred source on the Wazuh manager:

```text
/var/ossec/logs/alerts/alerts.json
```

Copy the relevant alert file to the analysis machine, for example:

```text
.\wazuh_exports\alerts.json
```

The pipeline accepts:

- Wazuh `alerts.json` JSONL format.
- JSON arrays.
- Wazuh dashboard JSON exports.
- CSV exports.

## 6. Run Lexical Pipeline Only

This is useful before executing Wazuh comparison:

```powershell
python .\thesis_wazuh_pipeline\pipeline.py run `
  --dataset "C:\Users\alsoh\Downloads\powershell_scriptblock_dataset_final_thesis_v4_package\powershell_scriptblock_samples_final_thesis_v4.json" `
  --out-dir ".\thesis_wazuh_pipeline\results\lexical_only" `
  --threshold 6
```

## 7. Run Standard Wazuh Baseline Comparison

```powershell
python .\thesis_wazuh_pipeline\pipeline.py run `
  --dataset "C:\Users\alsoh\Downloads\powershell_scriptblock_dataset_final_thesis_v4_package\powershell_scriptblock_samples_final_thesis_v4.json" `
  --alerts ".\wazuh_exports\alerts.json" `
  --out-dir ".\thesis_wazuh_pipeline\results\wazuh_standard_baseline" `
  --threshold 6
```

The output compares:

- `wazuh_standard`
- `lexical_pipeline`
- `hybrid_or`

## 8. Tune the Lexical Threshold

Run:

```powershell
python .\thesis_wazuh_pipeline\pipeline.py tune `
  --dataset "C:\Users\alsoh\Downloads\powershell_scriptblock_dataset_final_thesis_v4_package\powershell_scriptblock_samples_final_thesis_v4.json" `
  --out-dir ".\thesis_wazuh_pipeline\results\tuning" `
  --max-fpr 0.10
```

Use threshold tuning carefully in the thesis. If you choose a threshold based on
the same dataset, say so clearly. A cleaner method is to choose the threshold on
a calibration split and report final results on a separate test split.

## 9. Thesis Tables

Use these files:

```text
metrics_overall.csv
metrics_by_obfuscation.csv
metrics_by_dataset_group.csv
metrics_by_tactic.csv
```

Recommended thesis table:

| Method | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Wazuh standard rules | ... | ... | ... | ... | ... | ... | ... | ... |
| Lexical pipeline | ... | ... | ... | ... | ... | ... | ... | ... |
| Hybrid OR | ... | ... | ... | ... | ... | ... | ... | ... |

## 10. Important Interpretation

A Wazuh alert does not mean a real attack happened. In this experiment, the
simulated malicious samples are inert indicator ScriptBlocks. The result means
that Wazuh detected an indicator in the telemetry.

This wording is important for the security and scientific framing of the thesis.
