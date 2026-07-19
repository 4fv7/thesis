#!/usr/bin/env python3
"""PowerShell lexical detector and Wazuh standard-rule evaluator.

For experiment runs, the lexical detector consumes ScriptBlockText directly
from Event ID 4104 in Microsoft-Windows-PowerShell/Operational. The JSON
dataset supplies labels and grouping metadata only. The pipeline removes the
neutral experiment marker, performs bounded non-executing reconstruction, and
evaluates a transparent lexical score. Stratified grouped cross-validation keeps
related behavior variants out of the same training and test folds. Wazuh alerts
form an independent standard-rule baseline for the same instrumented executions.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import html
import json
import math
import os
import random
import re
import shutil
import statistics
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence


LABELS = {"benign": 0, "simulated_malicious": 1}
SAMPLE_ID_RE = re.compile(r"\b[A-Z]{3}-\d{3}\b", re.I)
INSTRUMENT_ASSIGNMENT_RE = re.compile(
    r"^\s*\$sampleId\s*=\s*(['\"])(?P<sample_id>[A-Z]{3}-\d{3})\1\s*;", re.I
)
INSTRUMENT_MARKER_TEMPLATE_RE = re.compile(
    r";\s*Write-(?:Output|Host)\s*\(\s*(['\"])WAZUH_SAMPLE\s+\{0\}\1"
    r"\s*-f\s*\$sampleId\s*\)\s*;?\s*$", re.I | re.S
)
BACKTICK_LINE_CONTINUATION_RE = re.compile(r"`(?:\r\n|\r|\n)")
BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])")
STRING_LITERAL_RE = re.compile(
    r"'(?P<single>(?:''|[^'])*)'|\"(?P<double>(?:`.|[^\"`])*)\"",
    re.S,
)
WORD_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{2,}")


TOKEN_CATEGORIES: dict[str, tuple[str, ...]] = {
    "execution": (
        "invoke-expression",
        "iex",
        "encodedcommand",
        "encoded command",
        "executionpolicy bypass",
        "windowstyle hidden",
        "scriptblock",
        "get-command",
    ),
    "download": (
        "downloadstring",
        "invoke-webrequest",
        "invoke-restmethod",
        "webclient",
        "start-bitstransfer",
        "bitsadmin",
        "certutil",
        "serverxmlhttp",
        "responseText",
    ),
    "network_c2": (
        "tcpclient",
        "getstream",
        "resolve-dnsname",
        "nslookup",
        "defaultwebproxy",
        "user-agent",
        "jitter",
        "checkin",
        "cookie",
    ),
    "defense_evasion": (
        "amsiutils",
        "amsiinitfailed",
        "set-mppreference",
        "disableRealtimeMonitoring",
        "exclusionpath",
        "reflection.assembly",
        "assembly]::load",
        "frombase64string",
        "add-type",
        "createthread",
    ),
    "persistence": (
        "register-scheduledtask",
        "new-scheduledtaskaction",
        "schtasks",
        "new-itemproperty",
        "currentversion\\run",
        "new-service",
    ),
    "credential_access": (
        "invoke-mimikatz",
        "invoke-kerberoast",
        "outputformat hashcat",
        "select-string",
        "password",
        "credential",
        "samaccountname",
    ),
    "lolbin": (
        "certutil",
        "mshta",
        "regsvr32",
        "rundll32",
        "installutil",
        "msbuild",
        "bitsadmin",
    ),
    "collection": (
        "get-clipboard",
        "copyfromscreen",
        "compress-archive",
        "createfromdirectory",
        "collect.zip",
    ),
    "remote_execution": (
        "invoke-command",
        "new-pssession",
        "enter-pssession",
        "computername",
    ),
    "discovery": (
        "get-process",
        "get-childitem",
        "get-itemproperty",
        "get-adcomputer",
        "get-netuser",
        "win32_bios",
        "win32_process",
    ),
}

CATEGORY_POINTS = {
    "execution": 2,
    "download": 2,
    "network_c2": 2,
    "defense_evasion": 2,
    "persistence": 2,
    "credential_access": 2,
    "lolbin": 2,
    "collection": 1,
    "remote_execution": 1,
    "discovery": 1,
}

HIGH_RISK_CATEGORIES = {
    "execution",
    "download",
    "network_c2",
    "defense_evasion",
    "persistence",
    "credential_access",
    "lolbin",
    "remote_execution",
}


@dataclass
class Metrics:
    method: str
    group_field: str
    group_value: str
    sample_count: int
    positive_count: int
    negative_count: int
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float | None
    recall: float | None
    f1: float | None
    fpr: float | None
    specificity: float | None
    accuracy: float | None
    balanced_accuracy: float | None


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2)


def write_csv(
    path: Path,
    rows: list[dict[str, Any]],
    fieldnames: list[str] | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows and not fieldnames:
        path.write_text("", encoding="utf-8")
        return
    if fieldnames is None:
        fieldnames = list(dict.fromkeys(key for row in rows for key in row))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def canonical_space(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def normalize_line_endings(value: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n")


def normalize_backtick_line_continuation_rendering(value: str) -> str:
    """Normalize only backtick-newline to an equivalent backtick-space rendering."""

    return BACKTICK_LINE_CONTINUATION_RE.sub("` ", normalize_line_endings(value))


def extract_instrumented_sample_id(scriptblock: str) -> str | None:
    """Read an ID only from the assignment and terminal experiment marker."""

    assignment = INSTRUMENT_ASSIGNMENT_RE.search(scriptblock)
    marker = INSTRUMENT_MARKER_TEMPLATE_RE.search(scriptblock)
    if not assignment or not marker:
        return None
    return assignment.group("sample_id").upper()


def classify_scriptblock_fidelity(observed: str, expected: str) -> str:
    """Classify representation fidelity without hiding generic whitespace drift."""

    if observed == expected:
        return "exact"
    if normalize_line_endings(observed) == normalize_line_endings(expected):
        return "line_ending_only"
    if (
        normalize_backtick_line_continuation_rendering(observed)
        == normalize_backtick_line_continuation_rendering(expected)
        and BACKTICK_LINE_CONTINUATION_RE.search(expected)
    ):
        return "backtick_line_continuation_rendering"
    if canonical_space(observed) == canonical_space(expected):
        return "unclassified_whitespace_drift"
    return "content_drift"


def stable_int(value: str) -> int:
    return int(hashlib.sha256(value.encode("utf-8")).hexdigest()[:16], 16)


def truth_from_label(label: str) -> int:
    normalized = str(label).strip().lower()
    if normalized not in LABELS:
        raise ValueError(f"Unsupported label: {label!r}; expected {sorted(LABELS)}")
    return LABELS[normalized]


def derive_evaluation_group(row: dict[str, Any]) -> str:
    explicit = str(row.get("evaluation_group", "")).strip()
    if explicit:
        return explicit
    label = str(row.get("label", ""))
    family = str(row.get("behavior_family", "")).strip()
    if family:
        return f"{label}:{family}"
    scenario = str(row.get("scenario", row.get("id", "unknown")))
    scenario = re.sub(r"_v[12]$", "", scenario)
    scenario = re.sub(
        r"_(?:base64_literal_v1|string_concat_v1|backtick_v1|mixed_case_v1|"
        r"alias_reconstruction_v1|combined_obfuscation_v1)$",
        "",
        scenario,
    )
    return f"{label}:{scenario}"


def strip_instrumentation(scriptblock: str) -> str:
    text = scriptblock.strip()
    text = INSTRUMENT_ASSIGNMENT_RE.sub("", text, count=1).lstrip()
    text = re.sub(
        r"^\s*\$scenario\s*=\s*['\"][^'\"]*['\"]\s*;\s*",
        "",
        text,
        count=1,
        flags=re.I,
    )
    text = INSTRUMENT_MARKER_TEMPLATE_RE.sub("", text, count=1)
    return text.strip().rstrip(";")


def load_dataset(path: Path) -> list[dict[str, Any]]:
    data = read_json(path)
    if not isinstance(data, list):
        raise ValueError(f"Dataset must be a JSON list, got {type(data).__name__}")
    required = ("id", "label", "scriptblock")
    errors: list[str] = []
    for index, row in enumerate(data, start=1):
        if not isinstance(row, dict):
            errors.append(f"row {index} is not an object")
            continue
        missing = [field for field in required if not row.get(field)]
        if missing:
            errors.append(f"row {index} missing {missing}")
        try:
            truth_from_label(str(row.get("label", "")))
        except ValueError as exc:
            errors.append(str(exc))
    ids = [str(row.get("id", "")).upper() for row in data if isinstance(row, dict)]
    duplicates = [value for value, count in Counter(ids).items() if count > 1]
    if duplicates:
        errors.append(f"duplicate IDs: {duplicates[:10]}")
    if errors:
        raise ValueError("Dataset validation failed:\n- " + "\n- ".join(errors[:30]))
    return data


def dataset_validation_report(dataset: list[dict[str, Any]]) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    ids = {str(row["id"]).upper() for row in dataset}
    group_labels: dict[str, set[str]] = defaultdict(set)
    exact_analysis: dict[str, list[str]] = defaultdict(list)
    casefold_analysis: dict[str, list[str]] = defaultdict(list)
    metadata_leakage: list[dict[str, str]] = []
    source_missing: list[str] = []
    analysis_mismatch: list[str] = []
    instrumentation_residue: list[str] = []

    for row in dataset:
        sample_id = str(row["id"]).upper()
        scriptblock = str(row["scriptblock"])
        instrumented_id = extract_instrumented_sample_id(scriptblock)
        if instrumented_id is None:
            errors.append(
                f"{sample_id}: missing strict $sampleId assignment or terminal marker"
            )
        elif instrumented_id != sample_id:
            errors.append(f"{sample_id}: instrumentation declares {instrumented_id}")
        stripped = strip_instrumentation(scriptblock)
        if "$sampleId" in stripped or "WAZUH_SAMPLE" in stripped:
            instrumentation_residue.append(sample_id)
        declared = str(row.get("analysis_text", ""))
        if declared and canonical_space(stripped) != canonical_space(declared):
            analysis_mismatch.append(sample_id)
        group = derive_evaluation_group(row)
        group_labels[group].add(str(row["label"]))
        exact_analysis[stripped].append(sample_id)
        casefold_analysis[canonical_space(stripped).lower()].append(sample_id)
        for field in ("scenario", "dataset_group", "behavior_family"):
            value = str(row.get(field, "")).strip()
            if value and value.lower() in scriptblock.lower():
                metadata_leakage.append({"id": sample_id, "field": field, "value": value})
        if not row.get("source_reference_urls"):
            source_missing.append(sample_id)
        found_ids = {match.upper() for match in SAMPLE_ID_RE.findall(scriptblock)}
        if found_ids != {sample_id}:
            errors.append(f"{sample_id}: ScriptBlock IDs are {sorted(found_ids)}")

    mixed_groups = [group for group, labels in group_labels.items() if len(labels) > 1]
    if mixed_groups:
        errors.append(f"evaluation groups contain mixed labels: {mixed_groups[:10]}")
    if metadata_leakage:
        errors.append(f"metadata appears in {len(metadata_leakage)} ScriptBlocks")
    if analysis_mismatch:
        errors.append(f"declared analysis_text differs for {len(analysis_mismatch)} samples")
    if instrumentation_residue:
        errors.append(
            f"instrumentation remains in analysis text for {len(instrumentation_residue)} samples"
        )
    if source_missing:
        warnings.append(f"{len(source_missing)} samples lack source_reference_urls")

    cross_group_casefold_duplicates: list[dict[str, Any]] = []
    id_to_group = {str(row["id"]).upper(): derive_evaluation_group(row) for row in dataset}
    for sample_ids in casefold_analysis.values():
        groups = {id_to_group[value] for value in sample_ids}
        if len(sample_ids) > 1 and len(groups) > 1:
            cross_group_casefold_duplicates.append(
                {"ids": sample_ids, "evaluation_groups": sorted(groups)}
            )
    if cross_group_casefold_duplicates:
        errors.append(
            f"{len(cross_group_casefold_duplicates)} case-folded duplicates cross evaluation groups"
        )

    prefixes_by_label: dict[str, set[str]] = defaultdict(set)
    for row in dataset:
        prefixes_by_label[str(row["label"])].add(str(row["id"]).split("-", 1)[0])

    return {
        "sample_count": len(dataset),
        "unique_ids": len(ids),
        "label_counts": dict(Counter(str(row["label"]) for row in dataset)),
        "dataset_group_counts": dict(
            Counter(str(row.get("dataset_group", "")) for row in dataset)
        ),
        "obfuscation_counts": dict(
            Counter(str(row.get("obfuscation_type", "")) for row in dataset)
        ),
        "evaluation_group_count": len(group_labels),
        "exact_duplicate_core_sets": sum(len(values) > 1 for values in exact_analysis.values()),
        "casefold_duplicate_core_sets": sum(
            len(values) > 1 for values in casefold_analysis.values()
        ),
        "cross_group_casefold_duplicate_sets": cross_group_casefold_duplicates,
        "metadata_leakage": metadata_leakage,
        "analysis_text_mismatch_ids": analysis_mismatch,
        "instrumentation_residue_ids": instrumentation_residue,
        "source_missing_ids": source_missing,
        "id_prefixes_by_label": {
            label: sorted(values) for label, values in prefixes_by_label.items()
        },
        "errors": errors,
        "warnings": warnings,
        "valid": not errors,
    }


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def normalize_view(text: str) -> str:
    return canonical_space(text.replace("`", "")).lower()


def extract_string_literals(text: str) -> list[str]:
    values: list[str] = []
    for match in STRING_LITERAL_RE.finditer(text):
        if match.group("single") is not None:
            value = match.group("single").replace("''", "'")
        else:
            value = re.sub(r"`(.)", r"\1", match.group("double") or "")
        if "WAZUH_SAMPLE" in value or SAMPLE_ID_RE.fullmatch(value.strip()):
            continue
        values.append(value)
    return values


def printable_ratio(value: str) -> float:
    if not value:
        return 0.0
    return sum(char.isprintable() or char in "\r\n\t" for char in value) / len(value)


def decode_base64_candidates(texts: Sequence[str]) -> list[str]:
    decoded: list[str] = []
    seen: set[str] = set()
    for text in texts:
        for candidate in BASE64_RE.findall(text):
            if candidate in seen or len(candidate) > 16384:
                continue
            seen.add(candidate)
            padded = candidate + "=" * ((4 - len(candidate) % 4) % 4)
            try:
                raw = base64.b64decode(padded, validate=True)
            except (ValueError, base64.binascii.Error):
                continue
            for encoding in ("utf-16le", "utf-8", "ascii"):
                try:
                    value = raw.decode(encoding)
                except (UnicodeDecodeError, UnicodeError):
                    continue
                if len(value) >= 4 and printable_ratio(value) >= 0.85:
                    decoded.append(value[:8192])
                    break
    return decoded


def token_present(view: str, token: str) -> bool:
    token_normalized = normalize_view(token)
    if re.fullmatch(r"[a-z0-9_]{1,4}", token_normalized):
        return bool(re.search(rf"(?<![a-z0-9_]){re.escape(token_normalized)}(?![a-z0-9_])", view))
    return token_normalized in view


def category_hits(views: Sequence[str]) -> dict[str, list[str]]:
    normalized = [normalize_view(view) for view in views if view]
    output: dict[str, list[str]] = {}
    for category, tokens in TOKEN_CATEGORIES.items():
        output[category] = sorted(
            token for token in tokens if any(token_present(view, token) for view in normalized)
        )
    return output


def suspicious_mixed_case_tokens(text: str) -> list[str]:
    hits: list[str] = []
    for token in WORD_RE.findall(text):
        letters = [char for char in token if char.isalpha()]
        if len(letters) < 6 or not any(char.islower() for char in letters) or not any(
            char.isupper() for char in letters
        ):
            continue
        transitions = sum(
            left.islower() != right.islower() for left, right in zip(letters, letters[1:])
        )
        if transitions >= 4 and transitions / max(len(letters) - 1, 1) >= 0.35:
            hits.append(token)
    return sorted(set(hits))


def extract_features(scriptblock: str) -> dict[str, Any]:
    analysis_text = strip_instrumentation(scriptblock)
    if "$sampleId" in analysis_text or "WAZUH_SAMPLE" in analysis_text:
        raise ValueError("Experiment instrumentation remains in lexical analysis text")
    literals = extract_string_literals(analysis_text)
    joined_literals = "".join(literals)
    base_views = [analysis_text, analysis_text.replace("`", ""), joined_literals]
    decoded_views = decode_base64_candidates(base_views)
    all_views = [*base_views, *decoded_views]
    raw_hits = category_hits([analysis_text])
    all_hits = category_hits(all_views)
    decoded_hits = category_hits(decoded_views)

    recovered_hits = {
        category: sorted(set(all_hits[category]) - set(raw_hits[category]))
        for category in TOKEN_CATEGORIES
    }
    length = len(analysis_text)
    special_chars = len(re.findall(r"[^A-Za-z0-9\s]", analysis_text))
    base64_candidates = BASE64_RE.findall(analysis_text)
    mixed_case_hits = suspicious_mixed_case_tokens(analysis_text)
    short_literals = [value for value in literals if 0 < len(value) <= 16]

    features: dict[str, Any] = {
        "analysis_length": length,
        "line_count": analysis_text.count("\n") + 1,
        "token_count": len(re.findall(r"[A-Za-z0-9_\\.-]+", analysis_text)),
        "special_char_count": special_chars,
        "special_char_ratio": round(special_chars / max(length, 1), 6),
        "digit_ratio": round(sum(char.isdigit() for char in analysis_text) / max(length, 1), 6),
        "whitespace_ratio": round(
            sum(char.isspace() for char in analysis_text) / max(length, 1), 6
        ),
        "entropy": round(shannon_entropy(analysis_text), 6),
        "quoted_literal_count": len(literals),
        "short_literal_count": len(short_literals),
        "joined_literal_length": len(joined_literals),
        "base64_candidate_count": len(base64_candidates),
        "longest_base64_candidate": max(map(len, base64_candidates), default=0),
        "decoded_view_count": len(decoded_views),
        "backtick_count": analysis_text.count("`"),
        "concat_operator_count": len(re.findall(r"\s\+\s", analysis_text)),
        "join_operator_count": len(re.findall(r"(?i)-join|::Concat", analysis_text)),
        "format_operator_count": len(re.findall(r"(?i)\s-f\s", analysis_text)),
        "char_cast_count": len(re.findall(r"(?i)\[char\]", analysis_text)),
        "suspicious_mixed_case_count": len(mixed_case_hits),
        "suspicious_mixed_case_tokens": ";".join(mixed_case_hits),
    }
    total_categories = 0
    high_risk_categories = 0
    raw_total = 0
    all_total = 0
    recovered_total = 0
    decoded_total = 0
    for category in TOKEN_CATEGORIES:
        current = all_hits[category]
        features[f"{category}_hit_count"] = len(current)
        features[f"{category}_hits"] = ";".join(current)
        features[f"raw_{category}_hit_count"] = len(raw_hits[category])
        features[f"recovered_{category}_hit_count"] = len(recovered_hits[category])
        features[f"decoded_{category}_hit_count"] = len(decoded_hits[category])
        if current:
            total_categories += 1
            if category in HIGH_RISK_CATEGORIES:
                high_risk_categories += 1
        raw_total += len(raw_hits[category])
        all_total += len(current)
        recovered_total += len(recovered_hits[category])
        decoded_total += len(decoded_hits[category])
    features.update(
        {
            "indicator_category_count": total_categories,
            "high_risk_category_count": high_risk_categories,
            "raw_indicator_hit_count": raw_total,
            "indicator_hit_count": all_total,
            "recovered_indicator_hit_count": recovered_total,
            "decoded_indicator_hit_count": decoded_total,
        }
    )
    return features


def lexical_score(features: dict[str, Any]) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    def add(points: int, reason: str) -> None:
        nonlocal score
        score += points
        reasons.append(f"{points:+d}:{reason}")

    for category, points in CATEGORY_POINTS.items():
        if int(features[f"{category}_hit_count"]) > 0:
            add(points, f"category_{category}")
    if int(features["high_risk_category_count"]) >= 2:
        add(2, "multiple_high_risk_categories")
    if int(features["decoded_indicator_hit_count"]) > 0:
        add(2, "indicator_recovered_from_base64")
    if int(features["recovered_indicator_hit_count"]) > 0:
        add(2, "indicator_recovered_from_fragmentation")

    obfuscation_signals = 0
    if int(features["base64_candidate_count"]) > 0:
        obfuscation_signals += 1
        add(1, "base64_candidate")
    if int(features["backtick_count"]) >= 2:
        obfuscation_signals += 1
        add(1, "backtick_obfuscation")
    if int(features["concat_operator_count"]) >= 2 or int(
        features["join_operator_count"]
    ) > 0:
        obfuscation_signals += 1
        add(1, "string_reconstruction")
    if int(features["short_literal_count"]) >= 4:
        obfuscation_signals += 1
        add(1, "fragmented_literals")
    if int(features["suspicious_mixed_case_count"]) > 0:
        obfuscation_signals += 1
        add(1, "irregular_case")
    if int(features["format_operator_count"]) > 0 or int(features["char_cast_count"]) > 0:
        obfuscation_signals += 1
        add(1, "format_or_char_obfuscation")
    if obfuscation_signals >= 2:
        add(2, "combined_obfuscation")

    if (
        int(features["discovery_hit_count"]) > 0
        and int(features["high_risk_category_count"]) == 0
        and obfuscation_signals == 0
    ):
        add(-1, "discovery_only_correction")
    return max(score, 0), reasons


def predict_lexical(scriptblock: str, threshold: int) -> tuple[int, int, dict[str, Any], str]:
    features = extract_features(scriptblock)
    score, reasons = lexical_score(features)
    return int(score >= threshold), score, features, ";".join(reasons)


def iter_string_values(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for nested in value.values():
            yield from iter_string_values(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from iter_string_values(nested)



def normalize_wazuh_alert_text(value: str) -> str:
    """Undo serialization escaping used in Wazuh alert fields."""

    text = html.unescape(str(value))
    return text.replace('\\"', '"').replace("\\\\", "\\")


def extract_sample_ids_from_alert(alert: Any) -> set[str]:
    """Extract only IDs backed by the complete experiment instrumentation."""

    ids: set[str] = set()
    for text in iter_string_values(alert):
        sample_id = extract_instrumented_sample_id(
            normalize_wazuh_alert_text(text)
        )
        if sample_id is not None:
            ids.add(sample_id)
    return ids


def get_nested(value: Any, path: str, default: Any = "") -> Any:
    current = value
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def unwrap_alert(alert: dict[str, Any]) -> dict[str, Any]:
    source = alert.get("_source")
    return source if isinstance(source, dict) else alert


def normalize_alert(
    alert: dict[str, Any], source_line: int, expected_ids: set[str]
) -> tuple[dict[str, Any], str]:
    alert = unwrap_alert(alert)
    ids = extract_sample_ids_from_alert(alert)
    known_ids = sorted(ids & expected_ids)
    unknown_ids = sorted(ids - expected_ids)
    if len(known_ids) == 1 and not unknown_ids:
        mapping_status = "mapped"
        sample_id = known_ids[0]
    elif len(known_ids) > 1:
        mapping_status = "ambiguous"
        sample_id = ""
    elif unknown_ids:
        mapping_status = "unknown_id"
        sample_id = ""
    else:
        mapping_status = "unmapped"
        sample_id = ""
    rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
    agent = alert.get("agent") if isinstance(alert.get("agent"), dict) else {}
    event_id = get_nested(alert, "data.win.system.eventID", "")
    if not event_id:
        event_id = get_nested(alert, "data.win.system.eventId", "")
    normalized = {
        "sample_id": sample_id,
        "mapping_status": mapping_status,
        "candidate_ids": ";".join(sorted(ids)),
        "source_line": source_line,
        "timestamp": alert.get("timestamp", ""),
        "rule_id": str(rule.get("id", alert.get("rule_id", ""))),
        "rule_level": str(rule.get("level", alert.get("rule_level", ""))),
        "rule_description": str(
            rule.get("description", alert.get("rule_description", ""))
        ),
        "rule_groups": ";".join(map(str, rule.get("groups", []) or [])),
        "rule_mitre": json.dumps(rule.get("mitre", {}), ensure_ascii=False)
        if rule.get("mitre")
        else "",
        "agent_id": str(agent.get("id", alert.get("agent_id", ""))),
        "agent_name": str(agent.get("name", alert.get("agent_name", ""))),
        "event_id": str(event_id),
    }
    return normalized, mapping_status


def load_json_or_jsonl_alerts(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return [row for row in parsed if isinstance(row, dict)]
        if isinstance(parsed, dict):
            if isinstance(parsed.get("data"), list):
                return [row for row in parsed["data"] if isinstance(row, dict)]
            hits = get_nested(parsed, "hits.hits", None)
            if isinstance(hits, list):
                return [row for row in hits if isinstance(row, dict)]
            return [parsed]
    except json.JSONDecodeError:
        pass
    alerts: list[dict[str, Any]] = []
    for line in text.splitlines():
        try:
            parsed_line = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed_line, dict):
            alerts.append(parsed_line)
    return alerts

def load_event_channel_events(
    path: Path,
    expected_ids: set[str],
    dataset_by_id: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], dict[str, Any]]:
    """Load lexical input captured directly from the Windows Event channel.

    Every expected sample must occur exactly once as Event ID 4104, and its
    ScriptBlockText must match the instrumented dataset entry. The returned
    script text is the sole input to lexical feature extraction.
    """

    if not path.exists():
        raise FileNotFoundError(f"Event channel export not found: {path}")
    raw_events = load_json_or_jsonl_alerts(path)
    mapped_rows: list[dict[str, Any]] = []
    by_sample: dict[str, dict[str, Any]] = {}
    status_counts: Counter[str] = Counter()
    duplicate_sample_ids: list[str] = []

    for source_line, record in enumerate(raw_events, start=1):
        scriptblock_text = str(record.get("script_block_text", ""))
        declared_id = str(record.get("sample_id", "")).upper()
        instrumented_id = extract_instrumented_sample_id(scriptblock_text)
        if not scriptblock_text or instrumented_id is None:
            mapping_status = "invalid_instrumentation"
            sample_id = ""
        elif declared_id != instrumented_id:
            mapping_status = "declared_id_mismatch"
            sample_id = ""
        elif instrumented_id not in expected_ids:
            mapping_status = "unknown_id"
            sample_id = ""
        else:
            mapping_status = "mapped"
            sample_id = instrumented_id
        observed_event_id = str(record.get("event_id", ""))
        if mapping_status == "mapped" and observed_event_id != "4104":
            mapping_status = "wrong_event_id"
            sample_id = ""
        status_counts[mapping_status] += 1

        dataset_text = str(dataset_by_id[sample_id]["scriptblock"]) if sample_id else ""
        fidelity_status = (
            classify_scriptblock_fidelity(scriptblock_text, dataset_text)
            if sample_id
            else "not_mapped"
        )
        row = {
            "sample_id": sample_id,
            "declared_sample_id": declared_id,
            "mapping_status": mapping_status,
            "source_line": source_line,
            "channel": record.get(
                "channel", "Microsoft-Windows-PowerShell/Operational"
            ),
            "provider_name": record.get(
                "provider_name", "Microsoft-Windows-PowerShell"
            ),
            "computer": record.get("computer", ""),
            "record_id": record.get("record_id", ""),
            "time_created_utc": record.get("time_created_utc", ""),
            "event_id": str(record.get("event_id", "")),
            "scriptblock_id": record.get("script_block_id", ""),
            "message_number": record.get("message_number", ""),
            "message_total": record.get("message_total", ""),
            "dataset_fidelity_status": fidelity_status,
            "scriptblock_sha256": hashlib.sha256(
                scriptblock_text.encode("utf-8")
            ).hexdigest(),
            "scriptblock_text": scriptblock_text,
        }
        mapped_rows.append(row)
        if mapping_status == "mapped":
            if sample_id in by_sample:
                duplicate_sample_ids.append(sample_id)
            else:
                by_sample[sample_id] = row

    missing_sample_ids = sorted(expected_ids - set(by_sample))
    non_exact_ids = sorted(
        row["sample_id"]
        for row in mapped_rows
        if row["mapping_status"] == "mapped"
        and row["dataset_fidelity_status"] != "exact"
    )
    summary = {
        "source_field": (
            "Microsoft-Windows-PowerShell/Operational:4104/"
            "EventData/ScriptBlockText"
        ),
        "channel": "Microsoft-Windows-PowerShell/Operational",
        "event_id": 4104,
        "raw_event_count": len(raw_events),
        "mapped_sample_count": len(by_sample),
        "status_counts": dict(status_counts),
        "exact_dataset_scriptblock_match_count": sum(
            int(row["dataset_fidelity_status"] == "exact") for row in mapped_rows
        ),
        "non_exact_dataset_scriptblock_ids": non_exact_ids,
        "missing_sample_ids": missing_sample_ids,
        "duplicate_sample_ids": sorted(set(duplicate_sample_ids)),
    }
    fatal = (
        missing_sample_ids
        or duplicate_sample_ids
        or non_exact_ids
        or any(
            count
            for status, count in status_counts.items()
            if status != "mapped"
        )
    )
    if fatal:
        raise ValueError(
            "Strict Event 4104 channel validation failed: "
            + json.dumps(summary, ensure_ascii=False)
        )
    return mapped_rows, by_sample, summary


def load_csv_alerts(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8-sig", newline="", errors="replace") as handle:
        return list(csv.DictReader(handle))


def load_wazuh_alerts(
    path: Path | None,
    expected_ids: set[str],
    agent_name: str | None = None,
    event_id: str | None = None,
    standard_powershell_only: bool = True,
) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]], dict[str, Any]]:
    if path is None:
        return [], {}, {"raw_count": 0, "mapped_count": 0}
    if not path.exists():
        raise FileNotFoundError(f"Wazuh alert file not found: {path}")
    raw_alerts = load_csv_alerts(path) if path.suffix.lower() == ".csv" else load_json_or_jsonl_alerts(path)
    normalized: list[dict[str, Any]] = []
    by_sample: dict[str, list[dict[str, Any]]] = defaultdict(list)
    status_counts: Counter[str] = Counter()
    filtered_counts: Counter[str] = Counter()
    for index, alert in enumerate(raw_alerts, start=1):
        row, status = normalize_alert(alert, index, expected_ids)
        if agent_name and row["agent_name"] != agent_name:
            filtered_counts["agent_name"] += 1
            continue
        if event_id and row["event_id"] != str(event_id):
            filtered_counts["event_id"] += 1
            continue
        if standard_powershell_only:
            try:
                rule_id_value = int(row["rule_id"])
            except ValueError:
                rule_id_value = 0
            if not 91803 <= rule_id_value <= 92000:
                filtered_counts["non_powershell_standard_rule"] += 1
                continue
        normalized.append(row)
        status_counts[status] += 1
        if status == "mapped":
            by_sample[row["sample_id"]].append(row)
    summary = {
        "raw_count": len(raw_alerts),
        "retained_count": len(normalized),
        "status_counts": dict(status_counts),
        "filtered_counts": dict(filtered_counts),
        "mapped_alert_count": sum(len(values) for values in by_sample.values()),
        "mapped_sample_count": len(by_sample),
    }
    return normalized, by_sample, summary


def safe_div(numerator: int | float, denominator: int | float) -> float | None:
    return numerator / denominator if denominator else None


def metrics_from_pairs(
    method: str,
    truths: Sequence[int],
    predictions: Sequence[int],
    group_field: str = "all",
    group_value: str = "all",
) -> Metrics:
    tp = fp = tn = fn = 0
    for truth, prediction in zip(truths, predictions):
        if truth == 1 and prediction == 1:
            tp += 1
        elif truth == 0 and prediction == 1:
            fp += 1
        elif truth == 0 and prediction == 0:
            tn += 1
        else:
            fn += 1
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    fpr = safe_div(fp, fp + tn)
    specificity = safe_div(tn, tn + fp)
    f1 = None
    if precision is not None and recall is not None:
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = safe_div(tp + tn, len(truths))
    balanced_accuracy = None
    if recall is not None and specificity is not None:
        balanced_accuracy = (recall + specificity) / 2
    return Metrics(
        method=method,
        group_field=group_field,
        group_value=group_value,
        sample_count=len(truths),
        positive_count=tp + fn,
        negative_count=tn + fp,
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
        precision=precision,
        recall=recall,
        f1=f1,
        fpr=fpr,
        specificity=specificity,
        accuracy=accuracy,
        balanced_accuracy=balanced_accuracy,
    )


def compute_metrics(
    method: str,
    rows: Sequence[dict[str, Any]],
    prediction_field: str,
    group_field: str = "all",
    group_value: str = "all",
) -> Metrics:
    return metrics_from_pairs(
        method,
        [int(row["truth"]) for row in rows],
        [int(row[prediction_field]) for row in rows],
        group_field,
        group_value,
    )


def metrics_to_row(metric: Metrics) -> dict[str, Any]:
    row = metric.__dict__.copy()
    for key in (
        "precision",
        "recall",
        "f1",
        "fpr",
        "specificity",
        "accuracy",
        "balanced_accuracy",
    ):
        if row[key] is not None:
            row[key] = round(float(row[key]), 6)
    row.update({"TP": row.pop("tp"), "FP": row.pop("fp"), "TN": row.pop("tn"), "FN": row.pop("fn")})
    return row


def build_result_rows(
    dataset: list[dict[str, Any]],
    wazuh_by_sample: dict[str, list[dict[str, Any]]],
    scriptblock_events_by_sample: dict[str, dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    sample_rows: list[dict[str, Any]] = []
    feature_rows: list[dict[str, Any]] = []
    for sample in dataset:
        sample_id = str(sample["id"]).upper()
        observed_event = (
            scriptblock_events_by_sample.get(sample_id)
            if scriptblock_events_by_sample is not None
            else None
        )
        if scriptblock_events_by_sample is not None and observed_event is None:
            raise ValueError(f"Missing observed ScriptBlockText for {sample_id}")
        scriptblock = (
            str(observed_event["scriptblock_text"])
            if observed_event is not None
            else str(sample["scriptblock"])
        )
        lexical_input_source = (
            "windows_event_4104_scriptblocktext"
            if observed_event is not None
            else "dataset_scriptblock"
        )
        _, score, features, reasons = predict_lexical(scriptblock, threshold=10**6)
        alerts = wazuh_by_sample.get(sample_id, [])
        rule_ids = sorted({alert["rule_id"] for alert in alerts if alert.get("rule_id")})
        descriptions = sorted(
            {alert["rule_description"] for alert in alerts if alert.get("rule_description")}
        )
        levels = []
        for alert in alerts:
            try:
                levels.append(int(alert.get("rule_level", 0)))
            except (TypeError, ValueError):
                pass
        result = {
            "id": sample_id,
            "label": sample.get("label", ""),
            "truth": truth_from_label(str(sample.get("label", ""))),
            "class_id": sample.get("class_id", ""),
            "dataset_group": sample.get("dataset_group", ""),
            "scenario": sample.get("scenario", ""),
            "behavior_family": sample.get("behavior_family", ""),
            "evaluation_group": derive_evaluation_group(sample),
            "source_family": sample.get("source_family", ""),
            "tactic": sample.get("tactic", ""),
            "technique": sample.get("technique", ""),
            "mitre_attack_id": sample.get("mitre_attack_id", ""),
            "obfuscation_type": sample.get("obfuscation_type", ""),
            "safety_class": sample.get("safety_class", ""),
            "lexical_input_source": lexical_input_source,
            "scriptblock_event_id": (
                observed_event.get("scriptblock_id", "") if observed_event else ""
            ),
            "scriptblock_event_sha256": (
                observed_event.get("scriptblock_sha256", "") if observed_event else ""
            ),
            "analysis_text": strip_instrumentation(scriptblock),
            "lexical_score": score,
            "lexical_reasons": reasons,
            "wazuh_prediction": int(bool(alerts)),
            "wazuh_alert_count": len(alerts),
            "wazuh_rule_ids": ";".join(rule_ids),
            "wazuh_rule_levels": ";".join(map(str, sorted(set(levels)))),
            "wazuh_max_rule_level": max(levels, default=0),
            "wazuh_rule_descriptions": " | ".join(descriptions),
        }
        result.update({f"feature_{key}": value for key, value in features.items()})
        sample_rows.append(result)
        feature_rows.append(
            {"id": sample_id, "lexical_input_source": lexical_input_source, **features}
        )
    return sample_rows, feature_rows


def assign_group_folds(rows: list[dict[str, Any]], folds: int, seed: int) -> None:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[str(row["evaluation_group"])].append(row)
    by_truth: dict[int, list[tuple[str, list[dict[str, Any]]]]] = defaultdict(list)
    for name, members in groups.items():
        truths = {int(row["truth"]) for row in members}
        if len(truths) != 1:
            raise ValueError(f"Evaluation group {name!r} contains mixed labels")
        by_truth[truths.pop()].append((name, members))
    for truth, entries in by_truth.items():
        counts = [0] * folds
        entries.sort(key=lambda item: (-len(item[1]), stable_int(f"{seed}:{item[0]}")))
        for name, members in entries:
            candidates = [index for index, count in enumerate(counts) if count == min(counts)]
            fold = min(candidates, key=lambda value: stable_int(f"{seed}:{truth}:{name}:{value}"))
            for row in members:
                row["cv_fold"] = fold
            counts[fold] += len(members)


def threshold_metrics(rows: Sequence[dict[str, Any]], threshold: int) -> dict[str, Any]:
    metric = metrics_from_pairs(
        "lexical_pipeline",
        [int(row["truth"]) for row in rows],
        [int(row["lexical_score"]) >= threshold for row in rows],
    )
    result = metrics_to_row(metric)
    result["threshold"] = threshold
    return result


def select_threshold(
    rows: Sequence[dict[str, Any]],
    min_threshold: int,
    max_threshold: int,
    max_fpr: float,
) -> tuple[int, list[dict[str, Any]]]:
    candidates = [
        threshold_metrics(rows, threshold)
        for threshold in range(min_threshold, max_threshold + 1)
    ]
    for row in candidates:
        row["selection_max_fpr"] = max_fpr
        row["eligible_under_max_fpr"] = int(
            row["fpr"] is not None and float(row["fpr"]) <= max_fpr
        )
    eligible = [row for row in candidates if row["eligible_under_max_fpr"]]
    pool = eligible or candidates
    selected = max(
        pool,
        key=lambda row: (
            float(row["f1"] or 0.0),
            float(row["recall"] or 0.0),
            -float(row["fpr"] or 0.0),
            -int(row["threshold"]),
        ),
    )
    for row in candidates:
        row["selected"] = int(row is selected)
    return int(selected["threshold"]), candidates


def apply_grouped_cv(
    rows: list[dict[str, Any]],
    folds: int,
    seed: int,
    min_threshold: int,
    max_threshold: int,
    max_fpr: float,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    assign_group_folds(rows, folds, seed)
    selected_rows: list[dict[str, Any]] = []
    tuning_rows: list[dict[str, Any]] = []
    for fold in range(folds):
        training = [row for row in rows if int(row["cv_fold"]) != fold]
        testing = [row for row in rows if int(row["cv_fold"]) == fold]
        threshold, candidates = select_threshold(
            training, min_threshold, max_threshold, max_fpr
        )
        selected_training = next(row for row in candidates if row["threshold"] == threshold)
        selected_rows.append(
            {
                "fold": fold,
                "selected_threshold": threshold,
                "training_sample_count": len(training),
                "test_sample_count": len(testing),
                "training_f1": selected_training["f1"],
                "training_fpr": selected_training["fpr"],
                "training_recall": selected_training["recall"],
            }
        )
        for candidate in candidates:
            tuning_rows.append({"fold": fold, **candidate})
        for row in testing:
            row["cv_threshold"] = threshold
            row["lexical_prediction"] = int(int(row["lexical_score"]) >= threshold)
    return selected_rows, tuning_rows


def finalize_predictions(rows: list[dict[str, Any]]) -> None:
    for row in rows:
        lexical = int(row["lexical_prediction"])
        wazuh = int(row["wazuh_prediction"])
        row["hybrid_or_prediction"] = int(lexical or wazuh)
        row["hybrid_and_prediction"] = int(lexical and wazuh)


METHODS = (
    ("wazuh_standard", "wazuh_prediction"),
    ("lexical_pipeline", "lexical_prediction"),
    ("hybrid_or", "hybrid_or_prediction"),
    ("hybrid_and", "hybrid_and_prediction"),
)


def compute_all_metrics(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    outputs: dict[str, list[dict[str, Any]]] = {
        "metrics_overall": [
            metrics_to_row(compute_metrics(method, rows, field)) for method, field in METHODS
        ]
    }
    for group_field, output_name in (
        ("obfuscation_type", "metrics_by_obfuscation"),
        ("dataset_group", "metrics_by_dataset_group"),
        ("tactic", "metrics_by_tactic"),
        ("behavior_family", "metrics_by_behavior_family"),
        ("cv_fold", "metrics_by_cv_fold"),
    ):
        grouped: list[dict[str, Any]] = []
        values = sorted({str(row.get(group_field, "")) for row in rows})
        for value in values:
            subset = [row for row in rows if str(row.get(group_field, "")) == value]
            for method, field in METHODS:
                grouped.append(
                    metrics_to_row(
                        compute_metrics(method, subset, field, group_field, value)
                    )
                )
        outputs[output_name] = grouped
    return outputs


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return float("nan")
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def grouped_bootstrap(
    rows: list[dict[str, Any]], iterations: int, seed: int
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if iterations <= 0:
        return [], []
    group_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        group_rows[str(row["evaluation_group"])].append(row)
    groups_by_truth: dict[int, list[str]] = defaultdict(list)
    for name, members in group_rows.items():
        groups_by_truth[int(members[0]["truth"])].append(name)
    rng = random.Random(seed)
    metrics_distribution: dict[tuple[str, str], list[float]] = defaultdict(list)
    differences: dict[tuple[str, str, str], list[float]] = defaultdict(list)
    metric_names = ("precision", "recall", "f1", "fpr", "accuracy")

    for _ in range(iterations):
        sampled: list[dict[str, Any]] = []
        for truth in (0, 1):
            names = groups_by_truth[truth]
            for _index in range(len(names)):
                sampled.extend(group_rows[rng.choice(names)])
        replicate: dict[str, dict[str, Any]] = {}
        for method, field in METHODS:
            replicate[method] = metrics_to_row(compute_metrics(method, sampled, field))
            for metric_name in metric_names:
                value = replicate[method][metric_name]
                if value is not None:
                    metrics_distribution[(method, metric_name)].append(float(value))
        for left, right in (
            ("lexical_pipeline", "wazuh_standard"),
            ("hybrid_or", "lexical_pipeline"),
        ):
            for metric_name in ("f1", "recall", "fpr"):
                left_value = replicate[left][metric_name]
                right_value = replicate[right][metric_name]
                if left_value is not None and right_value is not None:
                    differences[(left, right, metric_name)].append(
                        float(left_value) - float(right_value)
                    )

    estimates = {
        method: metrics_to_row(compute_metrics(method, rows, field))
        for method, field in METHODS
    }
    ci_rows: list[dict[str, Any]] = []
    for (method, metric_name), values in metrics_distribution.items():
        ci_rows.append(
            {
                "method": method,
                "metric": metric_name,
                "estimate": estimates[method][metric_name],
                "ci_lower_95": round(percentile(values, 0.025), 6),
                "ci_upper_95": round(percentile(values, 0.975), 6),
                "iterations": iterations,
                "resampling_unit": "evaluation_group_stratified_by_label",
            }
        )
    difference_rows: list[dict[str, Any]] = []
    for (left, right, metric_name), values in differences.items():
        estimate = float(estimates[left][metric_name]) - float(estimates[right][metric_name])
        difference_rows.append(
            {
                "left_method": left,
                "right_method": right,
                "metric": metric_name,
                "estimate_difference": round(estimate, 6),
                "ci_lower_95": round(percentile(values, 0.025), 6),
                "ci_upper_95": round(percentile(values, 0.975), 6),
                "iterations": iterations,
            }
        )
    return ci_rows, difference_rows


def prevalence_adjusted_precision(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for method, field in METHODS:
        metric = metrics_to_row(compute_metrics(method, rows, field))
        recall = metric["recall"]
        fpr = metric["fpr"]
        if recall is None or fpr is None:
            continue
        for prevalence in (0.01, 0.05, 0.10, 0.50):
            numerator = float(recall) * prevalence
            denominator = numerator + float(fpr) * (1 - prevalence)
            output.append(
                {
                    "method": method,
                    "assumed_prevalence": prevalence,
                    "recall": recall,
                    "fpr": fpr,
                    "expected_precision": round(numerator / denominator, 6)
                    if denominator
                    else None,
                }
            )
    return output


def wazuh_level_sensitivity(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for minimum_level in (3, 4, 5, 7, 10, 12):
        field = f"wazuh_level_{minimum_level}_prediction"
        for row in rows:
            row[field] = int(int(row["wazuh_max_rule_level"]) >= minimum_level)
        metric = metrics_to_row(compute_metrics(f"wazuh_level_{minimum_level}", rows, field))
        metric["minimum_rule_level"] = minimum_level
        output.append(metric)
    return output


def update_dataset_with_results(
    dataset: list[dict[str, Any]], rows: list[dict[str, Any]], feature_rows: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    results = {row["id"]: row for row in rows}
    features = {row["id"]: {key: value for key, value in row.items() if key != "id"} for row in feature_rows}
    output: list[dict[str, Any]] = []
    for sample in dataset:
        sample_id = str(sample["id"]).upper()
        result = results[sample_id]
        updated = dict(sample)
        updated["features"] = features[sample_id]
        for field in (
            "lexical_score",
            "lexical_prediction",
            "lexical_reasons",
            "cv_fold",
            "cv_threshold",
            "wazuh_prediction",
            "wazuh_alert_count",
            "wazuh_rule_ids",
            "wazuh_rule_levels",
            "hybrid_or_prediction",
            "hybrid_and_prediction",
        ):
            updated[field] = result.get(field, "")
        output.append(updated)
    return output



def resolve_powershell_executable(explicit: str | None = None) -> str:
    if explicit:
        return explicit
    for name in ("powershell.exe", "pwsh.exe", "pwsh"):
        found = shutil.which(name)
        if found:
            return found
    legacy = Path(
        "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
    )
    if legacy.exists():
        return str(legacy)
    raise FileNotFoundError(
        "No PowerShell executable found. Use --powershell to specify one."
    )


def path_for_powershell(path: Path, executable: str) -> str:
    resolved = path.resolve()
    if os.name == "nt" or not executable.lower().endswith(".exe"):
        return str(resolved)
    converted = subprocess.run(
        ["wslpath", "-w", str(resolved)],
        check=True,
        capture_output=True,
        text=True,
    )
    return converted.stdout.strip()


def collect_event4104(args: argparse.Namespace) -> None:
    collector_script = Path(
        args.collector_script
        or Path(__file__).with_name("collect_event4104.ps1")
    )
    if not collector_script.exists():
        raise FileNotFoundError(f"Event collector not found: {collector_script}")

    executable = resolve_powershell_executable(args.powershell)
    paths = {
        "dataset": Path(args.dataset),
        "event_output": Path(args.event_output),
        "summary_output": Path(args.summary_output),
        "ready_file": Path(args.ready_file),
    }
    for key in ("event_output", "summary_output", "ready_file"):
        paths[key].parent.mkdir(parents=True, exist_ok=True)

    command = [
        executable,
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        path_for_powershell(collector_script, executable),
        "-DatasetPath",
        path_for_powershell(paths["dataset"], executable),
        "-EventExportPath",
        path_for_powershell(paths["event_output"], executable),
        "-SummaryPath",
        path_for_powershell(paths["summary_output"], executable),
        "-ReadyPath",
        path_for_powershell(paths["ready_file"], executable),
        "-TimeoutSeconds",
        str(args.timeout_seconds),
        "-CompletionGraceSeconds",
        str(args.completion_grace_seconds),
        "-PollMilliseconds",
        str(args.poll_milliseconds),
    ]
    completed = subprocess.run(command, check=False)
    if completed.returncode:
        raise SystemExit(completed.returncode)

def run_pipeline(args: argparse.Namespace) -> None:
    dataset_path = Path(args.dataset)
    out_dir = Path(args.out_dir)
    dataset = load_dataset(dataset_path)
    validation = dataset_validation_report(dataset)
    if not validation["valid"]:
        raise ValueError("Strict dataset validation failed: " + "; ".join(validation["errors"]))
    expected_ids = {str(row["id"]).upper() for row in dataset}
    dataset_by_id = {str(row["id"]).upper(): row for row in dataset}
    event_channel_path = Path(args.event_channel_events)
    event_channel_rows, event_channel_by_sample, event_channel_summary = (
        load_event_channel_events(
            event_channel_path,
            expected_ids,
            dataset_by_id,
        )
    )
    alerts, wazuh_by_sample, alert_summary = load_wazuh_alerts(
        Path(args.alerts) if args.alerts else None,
        expected_ids,
        agent_name=args.agent_name,
        event_id=args.event_id,
        standard_powershell_only=not args.include_all_wazuh_rules,
    )
    rows, feature_rows = build_result_rows(
        dataset, wazuh_by_sample, event_channel_by_sample
    )

    deployment_threshold, full_tuning = select_threshold(
        rows, args.min_threshold, args.max_threshold, args.max_fpr
    )
    cv_selected: list[dict[str, Any]] = []
    cv_tuning: list[dict[str, Any]] = []
    if args.evaluation_mode == "grouped_cv":
        cv_selected, cv_tuning = apply_grouped_cv(
            rows,
            args.folds,
            args.seed,
            args.min_threshold,
            args.max_threshold,
            args.max_fpr,
        )
    else:
        fixed_threshold = args.threshold if args.threshold is not None else deployment_threshold
        for row in rows:
            row["cv_fold"] = ""
            row["cv_threshold"] = fixed_threshold
            row["lexical_prediction"] = int(int(row["lexical_score"]) >= fixed_threshold)
        cv_selected = [{"fold": "fixed", "selected_threshold": fixed_threshold}]
    for row in rows:
        row["deployment_threshold"] = deployment_threshold
        row["lexical_prediction_full_fit"] = int(
            int(row["lexical_score"]) >= deployment_threshold
        )
    finalize_predictions(rows)

    metrics = compute_all_metrics(rows)
    confidence, differences = grouped_bootstrap(
        rows, args.bootstrap_iterations, args.seed
    )
    prevalence = prevalence_adjusted_precision(rows)
    level_sensitivity = wazuh_level_sensitivity(rows)
    updated_dataset = update_dataset_with_results(dataset, rows, feature_rows)

    write_json(out_dir / "dataset_validation.json", validation)
    write_csv(out_dir / "sample_results.csv", rows)
    write_json(out_dir / "sample_results.json", rows)
    write_csv(out_dir / "feature_values.csv", feature_rows)
    write_json(out_dir / "dataset_with_results.json", updated_dataset)
    write_csv(out_dir / "wazuh_alerts_mapped.csv", alerts)
    write_json(out_dir / "alert_mapping_summary.json", alert_summary)
    write_csv(out_dir / "event_channel_events_mapped.csv", event_channel_rows)
    write_json(
        out_dir / "event_channel_mapping_summary.json",
        event_channel_summary,
    )
    for name, metric_rows in metrics.items():
        write_csv(out_dir / f"{name}.csv", metric_rows)
    write_csv(out_dir / "cv_selected_thresholds.csv", cv_selected)
    write_csv(out_dir / "cv_threshold_tuning.csv", cv_tuning)
    write_csv(out_dir / "threshold_tuning_full.csv", full_tuning)
    write_csv(out_dir / "metrics_confidence_intervals.csv", confidence)
    write_csv(out_dir / "metric_differences_bootstrap.csv", differences)
    write_csv(out_dir / "prevalence_adjusted_precision.csv", prevalence)
    write_csv(out_dir / "wazuh_level_sensitivity.csv", level_sensitivity)

    summary = {
        "dataset_path": str(dataset_path.resolve()),
        "dataset_sha256": hashlib.sha256(dataset_path.read_bytes()).hexdigest(),
        "alert_path": str(Path(args.alerts).resolve()) if args.alerts else None,
        "alert_sha256": hashlib.sha256(Path(args.alerts).read_bytes()).hexdigest()
        if args.alerts
        else None,
        "event_channel_path": str(event_channel_path.resolve()),
        "event_channel_sha256": hashlib.sha256(
            event_channel_path.read_bytes()
        ).hexdigest(),
        "lexical_input_source": (
            "Microsoft-Windows-PowerShell/Operational:4104/"
            "EventData/ScriptBlockText"
        ),
        "event_channel_mapping": event_channel_summary,
        "out_dir": str(out_dir.resolve()),
        "evaluation_mode": args.evaluation_mode,
        "folds": args.folds if args.evaluation_mode == "grouped_cv" else None,
        "seed": args.seed,
        "max_fpr_for_threshold_selection": args.max_fpr,
        "deployment_threshold_full_dataset": deployment_threshold,
        "cv_selected_thresholds": cv_selected,
        "sample_count": len(dataset),
        "alert_mapping": alert_summary,
        "overall_metrics": metrics["metrics_overall"],
        "bootstrap_iterations": args.bootstrap_iterations,
        "interpretation": (
            "Lexical features are computed from ScriptBlockText captured directly "
            "from the Windows PowerShell Operational channel. Primary lexical metrics "
            "are out-of-fold estimates grouped by behavior family. Wazuh metrics use "
            "only standard-rule alerts from the same instrumented executions."
        ),
    }
    write_json(out_dir / "run_summary.json", summary)
    print(json.dumps(summary, indent=2, ensure_ascii=False))


def tune_thresholds(args: argparse.Namespace) -> None:
    dataset = load_dataset(Path(args.dataset))
    validation = dataset_validation_report(dataset)
    if not validation["valid"]:
        raise ValueError("Dataset validation failed")
    expected_ids = {str(row["id"]).upper() for row in dataset}
    dataset_by_id = {str(row["id"]).upper(): row for row in dataset}
    _, event_channel_by_sample, _ = load_event_channel_events(
        Path(args.event_channel_events),
        expected_ids,
        dataset_by_id,
    )
    rows, _ = build_result_rows(dataset, {}, event_channel_by_sample)
    selected, candidates = select_threshold(
        rows, args.min_threshold, args.max_threshold, args.max_fpr
    )
    out_dir = Path(args.out_dir)
    write_csv(out_dir / "threshold_tuning.csv", candidates)
    write_json(
        out_dir / "threshold_tuning_summary.json",
        {
            "selected_threshold": selected,
            "max_fpr": args.max_fpr,
            "scope": "descriptive_full_dataset_not_an_unbiased_performance_estimate",
        },
    )
    print(json.dumps({"selected_threshold": selected}, indent=2))


def summarize_dataset(args: argparse.Namespace) -> None:
    dataset = load_dataset(Path(args.dataset))
    report = dataset_validation_report(dataset)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    lengths = [len(strip_instrumentation(str(row["scriptblock"]))) for row in dataset]
    print(
        json.dumps(
            {
                "analysis_length_min": min(lengths),
                "analysis_length_median": statistics.median(lengths),
                "analysis_length_max": max(lengths),
            },
            indent=2,
        )
    )


def validate_dataset_command(args: argparse.Namespace) -> None:
    dataset = load_dataset(Path(args.dataset))
    report = dataset_validation_report(dataset)
    if args.out:
        write_json(Path(args.out), report)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    if not report["valid"]:
        raise SystemExit(2)


def add_threshold_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--min-threshold", type=int, default=1)
    parser.add_argument("--max-threshold", type=int, default=24)
    parser.add_argument("--max-fpr", type=float, default=0.10)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="PowerShell Event 4104 lexical and Wazuh evaluation pipeline"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    summarize = subparsers.add_parser("summarize")
    summarize.add_argument("--dataset", required=True)
    summarize.set_defaults(func=summarize_dataset)

    validate = subparsers.add_parser("validate")
    validate.add_argument("--dataset", required=True)
    validate.add_argument("--out")
    validate.set_defaults(func=validate_dataset_command)

    collect = subparsers.add_parser(
        "collect-event4104",
        help="Capture instrumented Event ID 4104 records directly from Windows",
    )
    collect.add_argument("--dataset", required=True)
    collect.add_argument("--event-output", required=True)
    collect.add_argument("--summary-output", required=True)
    collect.add_argument("--ready-file", required=True)
    collect.add_argument("--collector-script")
    collect.add_argument("--powershell")
    collect.add_argument("--timeout-seconds", type=int, default=600)
    collect.add_argument("--completion-grace-seconds", type=int, default=8)
    collect.add_argument("--poll-milliseconds", type=int, default=250)
    collect.set_defaults(func=collect_event4104)

    run = subparsers.add_parser("run")
    run.add_argument("--dataset", required=True)
    run.add_argument(
        "--event-channel-events",
        required=True,
        help=(
            "JSONL captured directly from Microsoft-Windows-PowerShell/Operational "
            "Event ID 4104"
        ),
    )
    run.add_argument("--alerts")
    run.add_argument("--out-dir", required=True)
    run.add_argument("--evaluation-mode", choices=("grouped_cv", "fixed"), default="grouped_cv")
    run.add_argument("--threshold", type=int)
    run.add_argument("--folds", type=int, default=5)
    run.add_argument("--seed", type=int, default=20260711)
    run.add_argument("--bootstrap-iterations", type=int, default=2000)
    run.add_argument("--agent-name")
    run.add_argument("--event-id")
    run.add_argument("--include-all-wazuh-rules", action="store_true")
    add_threshold_arguments(run)
    run.set_defaults(func=run_pipeline)

    tune = subparsers.add_parser("tune")
    tune.add_argument("--dataset", required=True)
    tune.add_argument("--event-channel-events", required=True)
    tune.add_argument("--out-dir", required=True)
    add_threshold_arguments(tune)
    tune.set_defaults(func=tune_thresholds)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
