#!/usr/bin/env python3
"""Export manager receipts and standard Wazuh alerts for one dataset run."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

INSTRUMENT_ASSIGNMENT_RE = re.compile(
    r"^\s*\$sampleId\s*=\s*(['\"])(?P<sample_id>PST-\d{3})\1\s*;", re.I
)
INSTRUMENT_MARKER_TEMPLATE_RE = re.compile(
    r";\s*Write-(?:Output|Host)\s*\(\s*(['\"])WAZUH_SAMPLE\s+\{0\}\1"
    r"\s*-f\s*\$sampleId\s*\)\s*;?\s*$", re.I | re.S
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def nested(record: dict[str, Any], *keys: str) -> Any:
    value: Any = record
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def normalize_alert_text(value: str) -> str:
    text = html.unescape(str(value))
    return text.replace('\\\"', '"').replace("\\\\", "\\")


def record_scriptblock_text(record: dict[str, Any]) -> str:
    value = nested(record, "data", "win", "eventdata", "scriptBlockText")
    if isinstance(value, list):
        value = "".join(str(part) for part in value)
    return normalize_alert_text(value) if isinstance(value, str) else ""


def extract_instrumented_sample_id(scriptblock: str) -> str | None:
    assignment = INSTRUMENT_ASSIGNMENT_RE.search(scriptblock)
    marker = INSTRUMENT_MARKER_TEMPLATE_RE.search(scriptblock)
    if not assignment or not marker:
        return None
    return assignment.group("sample_id").upper()


def load_expected_ids(dataset_path: Path) -> set[str]:
    payload = json.loads(dataset_path.read_text(encoding="utf-8-sig"))
    rows = payload.get("samples", payload) if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        raise SystemExit("Dataset must be a JSON list or contain a samples list")
    identifiers = {str(row["id"]).upper() for row in rows}
    if len(identifiers) != len(rows):
        raise SystemExit("Dataset contains duplicate IDs")
    return identifiers


def read_standard_alerts(
    path: Path,
    start_line: int,
    expected_ids: set[str],
    agent_name: str,
    event_id: str,
) -> tuple[list[dict[str, Any]], Counter[str], list[dict[str, Any]]]:
    records: list[dict[str, Any]] = []
    identifiers: Counter[str] = Counter()
    rejected: list[dict[str, Any]] = []

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            if line_number <= start_line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                rejected.append({"line": line_number, "reason": f"invalid JSON: {exc}"})
                continue
            if nested(record, "agent", "name") != agent_name:
                continue
            if str(nested(record, "data", "win", "system", "eventID")) != event_id:
                continue
            try:
                rule_id = int(nested(record, "rule", "id"))
            except (TypeError, ValueError):
                continue
            if not 91803 <= rule_id <= 92000:
                continue

            scriptblock_text = record_scriptblock_text(record)
            if not INSTRUMENT_ASSIGNMENT_RE.search(scriptblock_text):
                continue
            sample_id = extract_instrumented_sample_id(scriptblock_text)
            if sample_id is None:
                rejected.append(
                    {"line": line_number, "reason": "invalid experiment instrumentation"}
                )
                continue
            if sample_id not in expected_ids:
                rejected.append(
                    {
                        "line": line_number,
                        "reason": "unknown sample ID in strict instrumentation",
                        "id": sample_id,
                    }
                )
                continue
            identifiers[sample_id] += 1
            records.append(record)

    return records, identifiers, rejected


def read_manager_events(
    path: Path,
    start_line: int,
    expected_ids: set[str],
    agent_name: str,
    event_id: str,
) -> tuple[list[dict[str, Any]], Counter[str], list[dict[str, Any]]]:
    """Read strict Event-4104 receipts without treating them as detections."""

    records: list[dict[str, Any]] = []
    identifiers: Counter[str] = Counter()
    rejected: list[dict[str, Any]] = []

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            if line_number <= start_line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                rejected.append({"line": line_number, "reason": f"invalid JSON: {exc}"})
                continue
            if nested(record, "agent", "name") != agent_name:
                continue
            if str(nested(record, "data", "win", "system", "eventID")) != event_id:
                continue

            scriptblock_text = record_scriptblock_text(record)
            if not INSTRUMENT_ASSIGNMENT_RE.search(scriptblock_text):
                continue
            sample_id = extract_instrumented_sample_id(scriptblock_text)
            if sample_id is None:
                rejected.append(
                    {"line": line_number, "reason": "invalid experiment instrumentation"}
                )
                continue
            if sample_id not in expected_ids:
                rejected.append(
                    {
                        "line": line_number,
                        "reason": "unknown sample ID in strict instrumentation",
                        "id": sample_id,
                    }
                )
                continue
            identifiers[sample_id] += 1
            records.append(record)

    return records, identifiers, rejected


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")))
            handle.write("\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export manager receipts and standard Wazuh alerts for a dataset run"
    )
    parser.add_argument("--capture-start", type=Path, required=True)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--agent-name", default="Windows-Host")
    parser.add_argument("--event-id", default="4104")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    capture = json.loads(args.capture_start.read_text(encoding="utf-8"))
    expected = load_expected_ids(args.dataset)
    args.output_dir.mkdir(parents=True, exist_ok=True)

    manager_events, manager_ids, manager_rejected = read_manager_events(
        Path(capture["manager_events_path"]),
        int(capture["manager_events_start_line"]),
        expected,
        args.agent_name,
        args.event_id,
    )
    manager_path = args.output_dir / "manager_event4104_receipts.jsonl"
    write_jsonl(manager_path, manager_events)

    alerts, alert_ids, rejected = read_standard_alerts(
        Path(capture["alerts_path"]),
        int(capture["alerts_start_line"]),
        expected,
        args.agent_name,
        args.event_id,
    )
    alert_path = args.output_dir / "alerts_standard_rules_dataset_run.jsonl"
    write_jsonl(alert_path, alerts)

    rule_counts = Counter(str(nested(row, "rule", "id")) for row in alerts)
    unalerted_ids = sorted(expected - set(alert_ids))
    summary = {
        "exported_at_utc": datetime.now(timezone.utc).isoformat(),
        "capture_start": capture,
        "expected_sample_count": len(expected),
        "manager_event_record_count": len(manager_events),
        "manager_event_unique_sample_count": len(manager_ids),
        "manager_missing_ids": sorted(expected - set(manager_ids)),
        "manager_duplicate_sample_ids": {
            sample_id: count
            for sample_id, count in sorted(manager_ids.items())
            if count != 1
        },
        "manager_rejected_records": manager_rejected,
        "manager_events_sha256": sha256(manager_path),
        "manager_events_used_as_lexical_input": False,
        "standard_alert_record_count": len(alerts),
        "standard_alert_unique_sample_count": len(alert_ids),
        "unalerted_sample_count": len(unalerted_ids),
        "standard_alerts_per_sample": dict(sorted(alert_ids.items())),
        "rejected_records": rejected,
        "standard_rule_counts": dict(sorted(rule_counts.items())),
        "alerts_sha256": sha256(alert_path),
        "dataset_sha256": sha256(args.dataset),
    }
    summary_path = args.output_dir / "capture_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))

    if manager_rejected:
        raise SystemExit("Wazuh manager capture contains rejected experiment records")
    if set(manager_ids) != expected or any(count != 1 for count in manager_ids.values()):
        raise SystemExit("Wazuh manager capture is incomplete or contains duplicate IDs")
    if rejected:
        raise SystemExit("Wazuh alert capture contains rejected experiment records")


if __name__ == "__main__":
    main()
