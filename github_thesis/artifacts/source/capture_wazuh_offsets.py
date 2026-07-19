#!/usr/bin/env python3
"""Record start offsets and hashes for a Wazuh dataset capture."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def line_count(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open("rb") as handle:
        return sum(1 for _ in handle)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Record the start of a Wazuh manager and alert capture"
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--alerts",
        type=Path,
        default=Path("/var/ossec/logs/alerts/alerts.json"),
    )
    parser.add_argument(
        "--manager-events",
        type=Path,
        default=Path("/var/ossec/logs/archives/archives.json"),
        help="Manager-side JSON event archive used only for receipt verification",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("/var/ossec/etc/ossec.conf"),
    )
    parser.add_argument(
        "--rules",
        type=Path,
        default=Path("/var/ossec/ruleset/rules/0915-win-powershell_rules.xml"),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    payload = {
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "alerts_path": str(args.alerts),
        "alerts_start_line": line_count(args.alerts),
        "manager_events_path": str(args.manager_events),
        "manager_events_start_line": line_count(args.manager_events),
        "manager_events_exists": args.manager_events.exists(),
        "ossec_conf_sha256": sha256(args.config),
        "powershell_rules_sha256": sha256(args.rules),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()

