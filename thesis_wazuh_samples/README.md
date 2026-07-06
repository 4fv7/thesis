# Wazuh PowerShell ScriptBlock Sample Set

This package contains a reproducible, thesis-safe sample set for testing Wazuh
built-in rules against PowerShell ScriptBlock telemetry.

The samples are designed for a controlled Windows 11 lab with PowerShell
ScriptBlock Logging and a Wazuh agent enabled.

## Safety model

- No real malware is included.
- No real C2 infrastructure is contacted.
- No credential dumping is performed.
- No persistence, defender tampering, or destructive action is executed.
- Samples marked as simulated malicious use inert strings, placeholders, safe
  decoding, or harmless string construction to create detection-relevant
  ScriptBlock content.

For the thesis text, call these entries `Testfälle`, `ScriptBlock-Samples`, or
`simulierte Angriffssamples`, not live payloads.

## Dataset layout

- `data/powershell_scriptblock_samples.csv`: 300 generated samples.
- `data/powershell_scriptblock_samples.json`: same data as JSON.
- `tools/generate_powershell_samples.py`: reproducible generator.
- `tools/run_wazuh_samples.ps1`: Windows PowerShell runner for the lab VM.

## Recommended first experiment

1. Enable PowerShell ScriptBlock Logging on the Windows 11 lab machine.
2. Confirm that the Wazuh agent forwards PowerShell Operational events.
3. Run only the standard Wazuh rules first.
4. Execute the sample set with `tools/run_wazuh_samples.ps1`.
5. Export Wazuh alerts and compare them with the labels in the CSV.

After this baseline, enrich Wazuh rules and repeat the same sample execution.

## Source families used for coverage

The sample taxonomy is derived from public defensive references:

- MITRE ATT&CK T1059.001 PowerShell
- Atomic Red Team T1059.001 PowerShell
- Wazuh PowerShell exploitation detection guidance
- SigmaHQ PowerShell detection rules
- Elastic Windows PowerShell detection rules
- Microsoft Sentinel detection logic
- LOLBAS living-off-the-land taxonomy
- Invoke-Obfuscation obfuscation categories

The dataset intentionally does not copy live malware or weaponized payloads.
