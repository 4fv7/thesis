# Thesis Wazuh PowerShell Detection Pipeline

This package contains the experiment pipeline for comparing:

1. Wazuh standard rule results.
2. A transparent lexical-feature detector.
3. A hybrid detector: Wazuh OR lexical detector.

It is designed for the thesis dataset:

`powershell_scriptblock_samples_final_thesis_v4.json`

The code uses only the Python standard library.

## Directory Contents

- `pipeline.py` - main Python pipeline.
- `tools/run_dataset_samples.ps1` - executes the dataset in the Windows 11 lab VM.
- `docs/SETUP_AND_EXPERIMENT.md` - complete setup and experiment instructions.
- `docs/WAZUH_AGENT_POWERHELL_CONFIG.md` - Wazuh agent configuration notes.

## Quick Start

From the repository/workspace root:

```powershell
python .\thesis_wazuh_pipeline\pipeline.py summarize `
  --dataset "C:\Users\alsoh\Downloads\powershell_scriptblock_dataset_final_thesis_v4_package\powershell_scriptblock_samples_final_thesis_v4.json"
```

Run lexical detection only:

```powershell
python .\thesis_wazuh_pipeline\pipeline.py run `
  --dataset "C:\Users\alsoh\Downloads\powershell_scriptblock_dataset_final_thesis_v4_package\powershell_scriptblock_samples_final_thesis_v4.json" `
  --out-dir ".\thesis_wazuh_pipeline\results\lexical_only" `
  --threshold 6
```

Run lexical detection and compare with exported Wazuh alerts:

```powershell
python .\thesis_wazuh_pipeline\pipeline.py run `
  --dataset "C:\Users\alsoh\Downloads\powershell_scriptblock_dataset_final_thesis_v4_package\powershell_scriptblock_samples_final_thesis_v4.json" `
  --alerts ".\wazuh_exports\alerts.json" `
  --out-dir ".\thesis_wazuh_pipeline\results\wazuh_standard_baseline" `
  --threshold 6
```

Test threshold choices:

```powershell
python .\thesis_wazuh_pipeline\pipeline.py tune `
  --dataset "C:\Users\alsoh\Downloads\powershell_scriptblock_dataset_final_thesis_v4_package\powershell_scriptblock_samples_final_thesis_v4.json" `
  --out-dir ".\thesis_wazuh_pipeline\results\tuning"
```

## Output Files

The pipeline writes:

- `sample_results.csv`
- `sample_results.json`
- `dataset_with_results.json`
- `feature_values.csv`
- `wazuh_alerts_mapped.csv`
- `metrics_overall.csv`
- `metrics_by_obfuscation.csv`
- `metrics_by_dataset_group.csv`
- `metrics_by_tactic.csv`
- `run_summary.json`

Use `metrics_overall.csv` and `metrics_by_obfuscation.csv` directly for thesis
tables.

## Safety Note

The dataset is expected to contain benign commands and inert simulated malicious
indicator strings. The runner refuses to execute unless the explicit lab flag is
provided. Run the dataset only inside the isolated Windows 11 lab VM configured
for the thesis experiment.
