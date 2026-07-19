from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("additional_analyses.py")
SPEC = importlib.util.spec_from_file_location("additional_analyses", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Could not load additional_analyses.py")
analysis = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = analysis
SPEC.loader.exec_module(analysis)


class AdditionalAnalysisTests(unittest.TestCase):
    def test_scaffold_normalization_removes_neutral_wrapper(self) -> None:
        text = "$indicator='IEX test'; Write-Output $indicator"
        normalized = analysis.normalize_for_baseline(text)
        self.assertNotIn("indicator", normalized)
        self.assertNotIn("write-output", normalized)
        self.assertEqual(normalized, "'iex test';")

    def test_confusion_metrics(self) -> None:
        metrics = analysis.confusion_metrics([1, 1, 0, 0], [1, 0, 1, 0])
        self.assertEqual(metrics["TP"], 1)
        self.assertEqual(metrics["FP"], 1)
        self.assertEqual(metrics["TN"], 1)
        self.assertEqual(metrics["FN"], 1)
        self.assertEqual(metrics["f1"], 0.5)
        self.assertEqual(metrics["fpr"], 0.5)

    def test_grouped_metrics_preserve_group_counts(self) -> None:
        rows = [
            {"truth": 1, "prediction": 1, "dataset_group": "positive"},
            {"truth": 1, "prediction": 0, "dataset_group": "positive"},
            {"truth": 0, "prediction": 0, "dataset_group": "negative"},
        ]
        result = analysis.grouped_metrics(rows, "dataset_group", "test")
        self.assertEqual(sum(int(row["sample_count"]) for row in result), 3)
        self.assertEqual(
            {row["group_value"] for row in result},
            {"negative", "positive"},
        )


if __name__ == "__main__":
    unittest.main()
