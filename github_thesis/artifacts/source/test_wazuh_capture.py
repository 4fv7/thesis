#!/usr/bin/env python3
"""Tests for the strict manager-side Event-4104 receipt export."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("export_wazuh_capture.py")
SPEC = importlib.util.spec_from_file_location("export_wazuh_capture", MODULE_PATH)
assert SPEC and SPEC.loader
TARGET = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TARGET)


def event(sample_id: str, *, agent: str = "Windows-Host", event_id: str = "4104") -> dict:
    script = (
        f"$sampleId='{sample_id}'; Write-Output 'safe'; "
        'Write-Output ("WAZUH_SAMPLE {0}" -f $sampleId)'
    )
    return {
        "agent": {"name": agent},
        "data": {
            "win": {
                "system": {"eventID": event_id},
                "eventdata": {"scriptBlockText": script},
            }
        },
    }


class ManagerReceiptExportTests(unittest.TestCase):
    def write_records(self, records: list[dict]) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "archives.json"
        path.write_text(
            "".join(json.dumps(record) + "\n" for record in records),
            encoding="utf-8",
        )
        return path

    def test_offset_and_event_filters(self) -> None:
        path = self.write_records(
            [
                event("PST-001"),
                event("PST-001"),
                event("PST-002"),
                event("PST-003", agent="other"),
                event("PST-003", event_id="4103"),
            ]
        )
        records, identifiers, rejected = TARGET.read_manager_events(
            path, 1, {"PST-001", "PST-002"}, "Windows-Host", "4104"
        )
        self.assertEqual(len(records), 2)
        self.assertEqual(dict(identifiers), {"PST-001": 1, "PST-002": 1})
        self.assertEqual(rejected, [])

    def test_unknown_instrumented_id_is_rejected(self) -> None:
        path = self.write_records([event("PST-999")])
        records, identifiers, rejected = TARGET.read_manager_events(
            path, 0, {"PST-001"}, "Windows-Host", "4104"
        )
        self.assertEqual(records, [])
        self.assertEqual(dict(identifiers), {})
        self.assertEqual(rejected[0]["id"], "PST-999")

    def test_duplicate_id_is_visible_in_counter(self) -> None:
        path = self.write_records([event("PST-001"), event("PST-001")])
        records, identifiers, rejected = TARGET.read_manager_events(
            path, 0, {"PST-001"}, "Windows-Host", "4104"
        )
        self.assertEqual(len(records), 2)
        self.assertEqual(identifiers["PST-001"], 2)
        self.assertEqual(rejected, [])


if __name__ == "__main__":
    unittest.main()