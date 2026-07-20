#!/usr/bin/env python3
"""Verify manager-side receipt of all instrumented Event ID 4104 records."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


SAMPLE_ASSIGNMENT = re.compile(
    r"(?is)^\s*\$sampleId\s*=\s*['\"](?P<id>PST-[0-9]{3})['\"]\s*;"
)


def nested(record: dict[str, Any], *keys: str) -> Any:
    value: Any = record
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def event_id(record: dict[str, Any]) -> str:
    value = nested(record, "data", "win", "system", "eventID")
    if isinstance(value, dict):
        value = value.get("#text") or value.get("value")
    return str(value or "")


def script_block_text(record: dict[str, Any]) -> str:
    value = nested(record, "data", "win", "eventdata", "scriptBlockText")
    if isinstance(value, list):
        return "".join(str(part) for part in value)
    return str(value or "")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run(args: argparse.Namespace) -> None:
    dataset = json.loads(args.dataset.read_text(encoding="utf-8"))
    expected_ids = {str(row["id"]).upper() for row in dataset}
    if len(expected_ids) != 300:
        raise ValueError(f"Expected 300 dataset IDs, got {len(expected_ids)}")

    mapping_rows: list[dict[str, object]] = []
    rejected: list[dict[str, object]] = []
    observed_ids: list[str] = []
    event_ids: Counter[str] = Counter()
    agent_names: Counter[str] = Counter()
    timestamps: list[str] = []

    with args.receipts.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            record = json.loads(line)
            observed_event_id = event_id(record)
            text = script_block_text(record)
            assignment = SAMPLE_ASSIGNMENT.search(text)
            marker_present = "WAZUH_SAMPLE" in text
            sample_id = assignment.group("id").upper() if assignment else ""
            agent_name = str(nested(record, "agent", "name") or "")
            timestamp = str(record.get("timestamp") or "")
            event_ids[observed_event_id] += 1
            agent_names[agent_name] += 1
            if timestamp:
                timestamps.append(timestamp)

            reasons: list[str] = []
            if observed_event_id != str(args.event_id):
                reasons.append("wrong_event_id")
            if agent_name != args.agent_name:
                reasons.append("wrong_agent")
            if not sample_id:
                reasons.append("missing_leading_sample_assignment")
            elif sample_id not in expected_ids:
                reasons.append("unknown_sample_id")
            if not marker_present:
                reasons.append("missing_terminal_marker")

            if reasons:
                rejected.append(
                    {
                        "line_number": line_number,
                        "sample_id": sample_id,
                        "reasons": ";".join(reasons),
                    }
                )
                continue

            observed_ids.append(sample_id)
            system = nested(record, "data", "win", "system") or {}
            mapping_rows.append(
                {
                    "sample_id": sample_id,
                    "timestamp": timestamp,
                    "agent_name": agent_name,
                    "event_id": observed_event_id,
                    "event_record_id": system.get("eventRecordID", ""),
                    "script_block_id": (
                        nested(record, "data", "win", "eventdata", "scriptBlockId")
                        or ""
                    ),
                    "fragment_count": (
                        nested(record, "data", "win", "eventdata", "messageTotal")
                        or ""
                    ),
                }
            )

    counts = Counter(observed_ids)
    duplicates = sorted(sample_id for sample_id, count in counts.items() if count != 1)
    missing = sorted(expected_ids - set(observed_ids))
    valid = (
        len(mapping_rows) == len(expected_ids)
        and not rejected
        and not missing
        and not duplicates
    )
    summary = {
        "valid": valid,
        "purpose": "manager-side transport and ingestion receipt verification only",
        "used_as_lexical_input": False,
        "dataset_sha256": sha256(args.dataset),
        "receipt_export_sha256": sha256(args.receipts),
        "raw_record_count": len(mapping_rows) + len(rejected),
        "accepted_record_count": len(mapping_rows),
        "unique_expected_sample_count": len(expected_ids),
        "unique_received_sample_count": len(set(observed_ids)),
        "missing_sample_ids": missing,
        "duplicate_sample_ids": duplicates,
        "rejected_records": rejected,
        "event_id_counts": dict(sorted(event_ids.items())),
        "agent_name_counts": dict(sorted(agent_names.items())),
        "first_timestamp": min(timestamps) if timestamps else None,
        "last_timestamp": max(timestamps) if timestamps else None,
    }

    args.output_summary.parent.mkdir(parents=True, exist_ok=True)
    args.output_summary.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    args.output_mapping.parent.mkdir(parents=True, exist_ok=True)
    with args.output_mapping.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(mapping_rows[0]))
        writer.writeheader()
        writer.writerows(sorted(mapping_rows, key=lambda row: str(row["sample_id"])))

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    if not valid:
        raise SystemExit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--receipts", type=Path, required=True)
    parser.add_argument("--output-summary", type=Path, required=True)
    parser.add_argument("--output-mapping", type=Path, required=True)
    parser.add_argument("--agent-name", default="Windows-Host")
    parser.add_argument("--event-id", type=int, default=4104)
    return parser


if __name__ == "__main__":
    run(build_parser().parse_args())
