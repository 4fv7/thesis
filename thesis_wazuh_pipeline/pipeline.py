#!/usr/bin/env python3
"""PowerShell ScriptBlock lexical detector and Wazuh comparison pipeline.

The pipeline reads the thesis JSON dataset, computes lexical features, applies a
transparent score-based detector, optionally imports Wazuh alerts, and exports
comparison metrics for Wazuh, lexical, and hybrid detection.

No external Python packages are required.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


SAMPLE_MARKER_RE = re.compile(r"WAZUH_SAMPLE\s+([A-Z]{3}-\d{3}|[A-Z]+-\d{3})", re.I)
SAMPLE_ID_RE = re.compile(r"\b(BEN|SIM|OBF|MAL|CLR)-\d{3}\b", re.I)

SUSPICIOUS_TOKENS = [
    "encodedcommand",
    "-encodedcommand",
    "frombase64string",
    "invoke-expression",
    "iex",
    "downloadstring",
    "invoke-webrequest",
    "iwr",
    "webclient",
    "start-bitstransfer",
    "bitsadmin",
    "certutil",
    "mshta",
    "regsvr32",
    "rundll32",
    "installutil",
    "msbuild",
    "register-scheduledtask",
    "new-scheduledtask",
    "set-itemproperty",
    "new-itemproperty",
    "currentversion\\run",
    "amsi",
    "amsiutils",
    "amsiinitfailed",
    "executionpolicy bypass",
    "-windowstyle hidden",
    "-w hidden",
    "-nop",
    "-noprofile",
    "add-type",
    "reflection.assembly",
    "assembly]::load",
    "invoke-command",
    "enter-pssession",
    "new-pssession",
    "resolve-dnsname",
    "defaultwebproxy",
    "convertto-securestring",
    "get-credential",
    "kerberoast",
    "invoke-kerberoast",
]

HIGH_RISK_TOKENS = [
    "frombase64string",
    "encodedcommand",
    "invoke-expression",
    "downloadstring",
    "amsiinitfailed",
    "register-scheduledtask",
    "currentversion\\run",
    "regsvr32",
    "rundll32",
    "mshta",
]

BENIGN_ADMIN_TOKENS = [
    "get-process",
    "get-service",
    "get-ciminstance",
    "get-winevent",
    "get-childitem",
    "get-netadapter",
    "get-netipconfiguration",
    "get-date",
    "convertto-json",
    "convertto-csv",
    "measure-object",
    "select-object",
    "test-path",
]

ALIAS_TOKENS = [
    "iex",
    "iwr",
    "wget",
    "curl",
    "saps",
    "gci",
    "gc ",
    "cat ",
    "ls ",
]

LOLBIN_TOKENS = [
    "certutil",
    "mshta",
    "regsvr32",
    "rundll32",
    "installutil",
    "msbuild",
    "bitsadmin",
]

BASE64_RE = re.compile(r"\b[A-Za-z0-9+/]{32,}={0,2}\b")
URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
CAMEL_SPLIT_RE = re.compile(r"([a-z])([A-Z])")


@dataclass
class Metrics:
    method: str
    group_field: str
    group_value: str
    sample_count: int
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float
    recall: float
    f1: float
    fpr: float
    specificity: float
    accuracy: float
    balanced_accuracy: float


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2)


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not fieldnames:
        fieldnames = sorted({key for row in rows for key in row.keys()})
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def load_dataset(path: Path) -> list[dict[str, Any]]:
    data = read_json(path)
    if not isinstance(data, list):
        raise ValueError(f"Dataset must be a JSON list, got {type(data).__name__}")
    required = ["id", "label", "scriptblock"]
    missing = [field for field in required if any(not row.get(field) for row in data)]
    if missing:
        raise ValueError(f"Dataset has missing required fields: {missing}")
    return data


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def normalize_for_token_match(text: str) -> str:
    lowered = text.lower()
    lowered = lowered.replace("`", "")
    lowered = CAMEL_SPLIT_RE.sub(r"\1 \2", lowered)
    lowered = re.sub(r"\s+", " ", lowered)
    return lowered


def count_token_hits(text: str, tokens: list[str]) -> tuple[int, list[str]]:
    normalized = normalize_for_token_match(text)
    hits: list[str] = []
    count = 0
    for token in tokens:
        token_norm = normalize_for_token_match(token)
        occurrences = normalized.count(token_norm)
        if occurrences:
            count += occurrences
            hits.append(token)
    return count, hits


def count_split_indicator_patterns(text: str) -> int:
    patterns = [
        r"['\"]i['\"]\s*\+\s*['\"]e['\"]\s*\+\s*['\"]x['\"]",
        r"['\"]invoke['\"]\s*\+\s*['\"]-?expression['\"]",
        r"['\"]down['\"]\s*\+\s*['\"]load['\"]\s*\+\s*['\"]string['\"]",
        r"['\"]from['\"]\s*\+\s*['\"]base64['\"]\s*\+\s*['\"]string['\"]",
        r"\$[A-Za-z0-9_]+\s*=\s*['\"][^'\"]{1,15}['\"]\s*\+",
    ]
    return sum(1 for pattern in patterns if re.search(pattern, text, re.I))


def extract_features(scriptblock: str) -> dict[str, Any]:
    length = len(scriptblock)
    special_chars = len(re.findall(r"[^a-zA-Z0-9\s]", scriptblock))
    digits = sum(char.isdigit() for char in scriptblock)
    uppercase = sum(char.isupper() for char in scriptblock)
    whitespace = sum(char.isspace() for char in scriptblock)
    base64_candidates = BASE64_RE.findall(scriptblock)
    suspicious_count, suspicious_hits = count_token_hits(scriptblock, SUSPICIOUS_TOKENS)
    high_risk_count, high_risk_hits = count_token_hits(scriptblock, HIGH_RISK_TOKENS)
    benign_count, benign_hits = count_token_hits(scriptblock, BENIGN_ADMIN_TOKENS)
    alias_count, alias_hits = count_token_hits(scriptblock, ALIAS_TOKENS)
    lolbin_count, lolbin_hits = count_token_hits(scriptblock, LOLBIN_TOKENS)
    urls = URL_RE.findall(scriptblock)
    ip_hits = IP_RE.findall(scriptblock)

    return {
        "length": length,
        "line_count": scriptblock.count("\n") + 1,
        "token_count": len(re.findall(r"[A-Za-z0-9_\\.-]+", scriptblock)),
        "special_char_count": special_chars,
        "special_char_ratio": round(special_chars / max(length, 1), 6),
        "digit_count": digits,
        "digit_ratio": round(digits / max(length, 1), 6),
        "uppercase_count": uppercase,
        "uppercase_ratio": round(uppercase / max(length, 1), 6),
        "whitespace_ratio": round(whitespace / max(length, 1), 6),
        "entropy": round(shannon_entropy(scriptblock), 6),
        "base64_candidate_count": len(base64_candidates),
        "longest_base64_candidate": max((len(value) for value in base64_candidates), default=0),
        "has_base64_indicator": bool(base64_candidates),
        "backtick_count": scriptblock.count("`"),
        "concat_operator_count": scriptblock.count("+"),
        "quote_count": scriptblock.count("'") + scriptblock.count('"'),
        "url_count": len(urls),
        "ip_like_count": len(ip_hits),
        "suspicious_token_count": suspicious_count,
        "suspicious_tokens": ";".join(sorted(set(suspicious_hits))),
        "high_risk_token_count": high_risk_count,
        "high_risk_tokens": ";".join(sorted(set(high_risk_hits))),
        "benign_admin_token_count": benign_count,
        "benign_admin_tokens": ";".join(sorted(set(benign_hits))),
        "alias_token_count": alias_count,
        "alias_tokens": ";".join(sorted(set(alias_hits))),
        "lolbin_token_count": lolbin_count,
        "lolbin_tokens": ";".join(sorted(set(lolbin_hits))),
        "split_indicator_pattern_count": count_split_indicator_patterns(scriptblock),
    }


def lexical_score(features: dict[str, Any]) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    def add(points: int, reason: str) -> None:
        nonlocal score
        score += points
        reasons.append(f"+{points}:{reason}")

    if features["suspicious_token_count"] >= 1:
        add(3, "suspicious_token")
    if features["suspicious_token_count"] >= 3:
        add(1, "multiple_suspicious_tokens")
    if features["high_risk_token_count"] >= 1:
        add(2, "high_risk_token")
    if features["has_base64_indicator"]:
        add(2, "base64_candidate")
    if features["longest_base64_candidate"] >= 80:
        add(1, "long_base64_candidate")
    if features["entropy"] >= 4.5:
        add(1, "medium_entropy")
    if features["entropy"] >= 5.0:
        add(1, "high_entropy")
    if features["special_char_ratio"] >= 0.14:
        add(1, "medium_special_char_ratio")
    if features["special_char_ratio"] >= 0.20:
        add(1, "high_special_char_ratio")
    if features["backtick_count"] >= 2:
        add(2, "backtick_obfuscation")
    if features["concat_operator_count"] >= 3:
        add(2, "string_concatenation")
    if features["split_indicator_pattern_count"] >= 1:
        add(2, "split_indicator_pattern")
    if features["alias_token_count"] >= 1:
        add(1, "powershell_alias")
    if features["lolbin_token_count"] >= 1:
        add(2, "lolbin_indicator")
    if features["url_count"] >= 1:
        add(1, "url_indicator")
    if features["ip_like_count"] >= 1:
        add(1, "ip_indicator")

    obfuscation_evidence = sum(
        [
            features["has_base64_indicator"],
            features["backtick_count"] >= 2,
            features["concat_operator_count"] >= 3,
            features["split_indicator_pattern_count"] >= 1,
            features["uppercase_ratio"] >= 0.12 and features["suspicious_token_count"] >= 1,
        ]
    )
    if obfuscation_evidence >= 2:
        add(2, "combined_obfuscation_evidence")

    if (
        features["benign_admin_token_count"] >= 2
        and features["suspicious_token_count"] == 0
        and features["lolbin_token_count"] == 0
        and not features["has_base64_indicator"]
    ):
        score -= 2
        reasons.append("-2:benign_admin_only")

    return max(score, 0), reasons


def predict_lexical(scriptblock: str, threshold: int) -> tuple[int, int, dict[str, Any], str]:
    features = extract_features(scriptblock)
    score, reasons = lexical_score(features)
    prediction = int(score >= threshold)
    return prediction, score, features, ";".join(reasons)


def iter_string_values(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for nested in value.values():
            yield from iter_string_values(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from iter_string_values(nested)


def extract_sample_id_from_alert(alert: Any) -> str | None:
    for text in iter_string_values(alert):
        marker_match = SAMPLE_MARKER_RE.search(text)
        if marker_match:
            return marker_match.group(1).upper()
    for text in iter_string_values(alert):
        id_match = SAMPLE_ID_RE.search(text)
        if id_match:
            return id_match.group(0).upper()
    return None


def get_nested(value: Any, path: str, default: Any = "") -> Any:
    current = value
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def normalize_alert(alert: dict[str, Any], source_line: int) -> dict[str, Any]:
    sample_id = extract_sample_id_from_alert(alert)
    rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
    agent = alert.get("agent") if isinstance(alert.get("agent"), dict) else {}
    return {
        "sample_id": sample_id or "",
        "source_line": source_line,
        "timestamp": alert.get("timestamp", ""),
        "rule_id": str(rule.get("id", "")),
        "rule_level": str(rule.get("level", "")),
        "rule_description": str(rule.get("description", "")),
        "rule_groups": ";".join(map(str, rule.get("groups", []) or [])),
        "rule_mitre": json.dumps(rule.get("mitre", {}), ensure_ascii=False) if rule.get("mitre") else "",
        "agent_id": str(agent.get("id", "")),
        "agent_name": str(agent.get("name", "")),
    }


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
            hits = get_nested(parsed, "hits.hits", [])
            if isinstance(hits, list):
                normalized = []
                for hit in hits:
                    if isinstance(hit, dict) and isinstance(hit.get("_source"), dict):
                        normalized.append(hit["_source"])
                    elif isinstance(hit, dict):
                        normalized.append(hit)
                return normalized
            return [parsed]
    except json.JSONDecodeError:
        pass

    alerts: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            parsed_line = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed_line, dict):
            alerts.append(parsed_line)
    return alerts


def load_csv_alerts(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8-sig", newline="", errors="replace") as handle:
        return list(csv.DictReader(handle))


def load_wazuh_alerts(path: Path | None) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    if path is None:
        return [], {}
    if not path.exists():
        raise FileNotFoundError(f"Wazuh alert file not found: {path}")

    if path.suffix.lower() == ".csv":
        raw_alerts = load_csv_alerts(path)
    else:
        raw_alerts = load_json_or_jsonl_alerts(path)

    normalized: list[dict[str, Any]] = []
    by_sample: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for index, alert in enumerate(raw_alerts, start=1):
        normalized_alert = normalize_alert(alert, index)
        normalized.append(normalized_alert)
        if normalized_alert["sample_id"]:
            by_sample[normalized_alert["sample_id"]].append(normalized_alert)
    return normalized, by_sample


def truth_from_label(label: str) -> int:
    return 0 if str(label).lower() == "benign" else 1


def compute_metrics(method: str, rows: list[dict[str, Any]], prediction_field: str, group_field: str, group_value: str) -> Metrics:
    tp = fp = tn = fn = 0
    for row in rows:
        truth = int(row["truth"])
        pred = int(row[prediction_field])
        if truth == 1 and pred == 1:
            tp += 1
        elif truth == 0 and pred == 1:
            fp += 1
        elif truth == 0 and pred == 0:
            tn += 1
        elif truth == 1 and pred == 0:
            fn += 1

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    accuracy = (tp + tn) / max(len(rows), 1)
    balanced_accuracy = (recall + specificity) / 2
    return Metrics(
        method=method,
        group_field=group_field,
        group_value=group_value,
        sample_count=len(rows),
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


def metrics_to_row(metric: Metrics) -> dict[str, Any]:
    row = metric.__dict__.copy()
    for key in ["precision", "recall", "f1", "fpr", "specificity", "accuracy", "balanced_accuracy"]:
        row[key] = round(float(row[key]), 6)
    row.update({"TP": row.pop("tp"), "FP": row.pop("fp"), "TN": row.pop("tn"), "FN": row.pop("fn")})
    return row


def build_result_rows(
    dataset: list[dict[str, Any]],
    wazuh_by_sample: dict[str, list[dict[str, Any]]],
    threshold: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    sample_rows: list[dict[str, Any]] = []
    feature_rows: list[dict[str, Any]] = []
    updated_dataset: list[dict[str, Any]] = []

    for sample in dataset:
        sample_id = str(sample["id"]).upper()
        scriptblock = str(sample.get("scriptblock", ""))
        lexical_prediction, score, features, reasons = predict_lexical(scriptblock, threshold)
        alerts = wazuh_by_sample.get(sample_id, [])
        wazuh_prediction = int(bool(alerts))
        hybrid_prediction = int(wazuh_prediction or lexical_prediction)
        rule_ids = sorted({alert["rule_id"] for alert in alerts if alert.get("rule_id")})
        descriptions = sorted({alert["rule_description"] for alert in alerts if alert.get("rule_description")})

        result_row = {
            "id": sample_id,
            "label": sample.get("label", ""),
            "truth": truth_from_label(str(sample.get("label", ""))),
            "class_id": sample.get("class_id", ""),
            "dataset_group": sample.get("dataset_group", ""),
            "benign_subtype": sample.get("benign_subtype", ""),
            "scenario": sample.get("scenario", ""),
            "source_family": sample.get("source_family", ""),
            "tactic": sample.get("tactic", ""),
            "technique": sample.get("technique", ""),
            "mitre_attack_id": sample.get("mitre_attack_id", ""),
            "obfuscation_type": sample.get("obfuscation_type", ""),
            "safety_class": sample.get("safety_class", ""),
            "lexical_score": score,
            "lexical_threshold": threshold,
            "lexical_prediction": lexical_prediction,
            "lexical_reasons": reasons,
            "wazuh_prediction": wazuh_prediction,
            "wazuh_alert_count": len(alerts),
            "wazuh_rule_ids": ";".join(rule_ids),
            "wazuh_rule_descriptions": " | ".join(descriptions),
            "hybrid_prediction": hybrid_prediction,
        }
        result_row.update({f"feature_{key}": value for key, value in features.items() if not isinstance(value, (dict, list))})
        sample_rows.append(result_row)

        feature_rows.append({"id": sample_id, **features})

        updated = dict(sample)
        updated["features"] = features
        updated["lexical_score"] = score
        updated["lexical_prediction"] = lexical_prediction
        updated["wazuh_alert_observed"] = bool(alerts)
        updated["wazuh_rule_id_observed"] = rule_ids
        updated["wazuh_rule_description"] = descriptions
        updated["final_notes"] = result_row["lexical_reasons"]
        updated_dataset.append(updated)

    return sample_rows, feature_rows, updated_dataset


def compute_all_metrics(sample_rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    methods = [
        ("wazuh_standard", "wazuh_prediction"),
        ("lexical_pipeline", "lexical_prediction"),
        ("hybrid_or", "hybrid_prediction"),
    ]

    outputs: dict[str, list[dict[str, Any]]] = {}

    overall = []
    for method, field in methods:
        overall.append(metrics_to_row(compute_metrics(method, sample_rows, field, "all", "all")))
    outputs["metrics_overall"] = overall

    for group_field, output_name in [
        ("obfuscation_type", "metrics_by_obfuscation"),
        ("dataset_group", "metrics_by_dataset_group"),
        ("tactic", "metrics_by_tactic"),
    ]:
        rows = []
        values = sorted({str(row.get(group_field, "")) for row in sample_rows})
        for value in values:
            subset = [row for row in sample_rows if str(row.get(group_field, "")) == value]
            if not subset:
                continue
            for method, field in methods:
                rows.append(metrics_to_row(compute_metrics(method, subset, field, group_field, value)))
        outputs[output_name] = rows

    return outputs


def run_pipeline(args: argparse.Namespace) -> None:
    dataset_path = Path(args.dataset)
    out_dir = Path(args.out_dir)
    alert_path = Path(args.alerts) if args.alerts else None

    dataset = load_dataset(dataset_path)
    normalized_alerts, wazuh_by_sample = load_wazuh_alerts(alert_path)
    sample_rows, feature_rows, updated_dataset = build_result_rows(dataset, wazuh_by_sample, args.threshold)
    metrics = compute_all_metrics(sample_rows)

    write_csv(out_dir / "sample_results.csv", sample_rows)
    write_json(out_dir / "sample_results.json", sample_rows)
    write_csv(out_dir / "feature_values.csv", feature_rows)
    write_json(out_dir / "dataset_with_results.json", updated_dataset)
    write_csv(out_dir / "wazuh_alerts_mapped.csv", normalized_alerts)
    for name, rows in metrics.items():
        write_csv(out_dir / f"{name}.csv", rows)

    summary = {
        "dataset_path": str(dataset_path),
        "alert_path": str(alert_path) if alert_path else None,
        "out_dir": str(out_dir),
        "threshold": args.threshold,
        "sample_count": len(dataset),
        "wazuh_alert_count_total": len(normalized_alerts),
        "wazuh_alert_count_mapped_to_samples": sum(len(values) for values in wazuh_by_sample.values()),
        "mapped_sample_count": len(wazuh_by_sample),
        "label_counts": Counter(str(row.get("label", "")) for row in dataset),
        "obfuscation_counts": Counter(str(row.get("obfuscation_type", "")) for row in dataset),
        "overall_metrics": metrics["metrics_overall"],
    }
    write_json(out_dir / "run_summary.json", summary)

    print(f"Wrote results to: {out_dir}")
    print(json.dumps(summary["overall_metrics"], indent=2, ensure_ascii=False))


def tune_thresholds(args: argparse.Namespace) -> None:
    dataset = load_dataset(Path(args.dataset))
    out_dir = Path(args.out_dir)
    rows: list[dict[str, Any]] = []
    for threshold in range(args.min_threshold, args.max_threshold + 1):
        sample_rows, _, _ = build_result_rows(dataset, {}, threshold)
        metric = compute_metrics("lexical_pipeline", sample_rows, "lexical_prediction", "all", "all")
        row = metrics_to_row(metric)
        row["threshold"] = threshold
        rows.append(row)

    write_csv(out_dir / "threshold_tuning.csv", rows)
    best_f1 = max(rows, key=lambda row: (row["f1"], -row["fpr"], row["recall"]))
    constrained = [row for row in rows if row["fpr"] <= args.max_fpr]
    best_constrained = max(constrained, key=lambda row: (row["f1"], row["recall"])) if constrained else None
    summary = {"best_f1": best_f1, "max_fpr": args.max_fpr, "best_under_max_fpr": best_constrained}
    write_json(out_dir / "threshold_tuning_summary.json", summary)
    print(json.dumps(summary, indent=2, ensure_ascii=False))


def summarize_dataset(args: argparse.Namespace) -> None:
    dataset = load_dataset(Path(args.dataset))
    print(f"Samples: {len(dataset)}")
    for field in ["label", "dataset_group", "obfuscation_type", "safety_class", "tactic", "mitre_attack_id"]:
        print(f"\n{field}")
        for key, value in Counter(str(row.get(field, "")) for row in dataset).most_common(40):
            print(f"  {key}: {value}")
    lengths = [len(str(row.get("scriptblock", ""))) for row in dataset]
    print("\nscriptblock_length")
    print(f"  min: {min(lengths)}")
    print(f"  median: {statistics.median(lengths)}")
    print(f"  max: {max(lengths)}")
    print(f"  unique_scriptblocks: {len(set(str(row.get('scriptblock', '')) for row in dataset))}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Thesis Wazuh PowerShell detection pipeline")
    subparsers = parser.add_subparsers(dest="command", required=True)

    summarize = subparsers.add_parser("summarize", help="Print dataset summary")
    summarize.add_argument("--dataset", required=True)
    summarize.set_defaults(func=summarize_dataset)

    run = subparsers.add_parser("run", help="Run lexical detection and optional Wazuh comparison")
    run.add_argument("--dataset", required=True)
    run.add_argument("--alerts", help="Wazuh alerts export as JSON, JSONL, or CSV")
    run.add_argument("--out-dir", required=True)
    run.add_argument("--threshold", type=int, default=6)
    run.set_defaults(func=run_pipeline)

    tune = subparsers.add_parser("tune", help="Evaluate lexical thresholds against dataset labels")
    tune.add_argument("--dataset", required=True)
    tune.add_argument("--out-dir", required=True)
    tune.add_argument("--min-threshold", type=int, default=1)
    tune.add_argument("--max-threshold", type=int, default=14)
    tune.add_argument("--max-fpr", type=float, default=0.10)
    tune.set_defaults(func=tune_thresholds)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
