#!/usr/bin/env python3
"""Verify the frozen experiment artifacts and repository references."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import re
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "artifacts/dataset/powershell_scriptblock_samples.json"
DATASET_SUMMARY = ROOT / "artifacts/dataset/dataset_summary.json"
SOURCE_MANIFEST = ROOT / "artifacts/dataset/source_manifest.json"
LOCAL_EVENTS = ROOT / "artifacts/messlauf/local_event4104_dataset_run.jsonl"
ALERTS = ROOT / "artifacts/messlauf/capture/alerts_standard_rules_dataset_run.jsonl"
MANAGER_RECEIPTS = ROOT / "artifacts/messlauf/capture/manager_event4104_receipts.jsonl"
RUN_SUMMARY = ROOT / "artifacts/messlauf/analysis/run_summary.json"
CAPTURE_SUMMARY = ROOT / "artifacts/messlauf/event4104_capture_summary.json"
RECEIPT_SUMMARY = ROOT / "artifacts/messlauf/analysis/manager_receipt_summary.json"
METRICS = ROOT / "artifacts/messlauf/analysis/metrics_overall.csv"
BASELINE_METRICS = ROOT / "artifacts/messlauf/analysis/char_ngram_baseline_metrics.csv"
TEX = ROOT / "Bachelorarbeit_Rashed_Alsuhaibi.tex"


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"[OK] {message}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def close(actual: float, expected: float, tolerance: float = 1e-6) -> bool:
    return math.isclose(actual, expected, rel_tol=0.0, abs_tol=tolerance)


def verify_dataset() -> None:
    dataset = read_json(DATASET)
    summary = read_json(DATASET_SUMMARY)

    check(sha256(DATASET) == summary["dataset_sha256"], "Datensatz-Prüfsumme")
    check(
        sha256(SOURCE_MANIFEST) == summary["source_manifest_sha256"],
        "Quellenmanifest-Prüfsumme",
    )
    check(len(dataset) == summary["sample_count"] == 300, "300 Datensatzfälle")

    ids = [sample["id"] for sample in dataset]
    check(len(ids) == len(set(ids)) == 300, "300 eindeutige neutrale IDs")
    check(
        Counter(sample["label"] for sample in dataset)
        == Counter({"benign": 150, "simulated_malicious": 150}),
        "ausgeglichene Klassenverteilung",
    )

    positive = [sample for sample in dataset if sample["label"] == "simulated_malicious"]
    families = Counter(sample["behavior_family"] for sample in positive)
    check(len(families) == 30, "30 positive Verhaltensfamilien")
    check(set(families.values()) == {5}, "fünf Varianten je positiver Verhaltensfamilie")
    check(
        sum(sample["dataset_group"] == "clear_indicator" for sample in positive) == 30,
        "30 klare positive Testfälle",
    )
    check(
        sum(sample["dataset_group"] == "obfuscated_indicator" for sample in positive)
        == 120,
        "120 obfuskierte positive Testfälle",
    )
    check(
        len({sample["scriptblock"] for sample in dataset}) == 300,
        "300 eindeutige instrumentierte ScriptBlocks",
    )


def verify_event_and_wazuh_exports() -> None:
    dataset = {sample["id"]: sample for sample in read_json(DATASET)}
    events = read_jsonl(LOCAL_EVENTS)
    check(len(events) == 300, "300 lokale Event-4104-Datensätze")
    check(
        all(int(event["event_id"]) == 4104 for event in events),
        "Event-ID 4104 in allen lokalen Datensätzen",
    )
    event_ids = [event["sample_id"] for event in events]
    check(len(event_ids) == len(set(event_ids)) == 300, "eindeutige lokale Event-Zuordnung")
    check(set(event_ids) == set(dataset), "vollständige lokale Event-Abdeckung")
    check(
        all(
            event["script_block_text"] == dataset[event["sample_id"]]["scriptblock"]
            for event in events
        ),
        "exakte Übereinstimmung der 300 ScriptBlockText-Werte",
    )

    capture = read_json(CAPTURE_SUMMARY)
    check(sha256(LOCAL_EVENTS) == capture["event_export_sha256"], "lokaler Event-Export-Hash")

    receipts = read_jsonl(MANAGER_RECEIPTS)
    check(len(receipts) == 300, "300 managerseitige Empfangsbelege")
    receipt_summary = read_json(RECEIPT_SUMMARY)
    check(receipt_summary["valid"] is True, "gültiger managerseitiger Empfangsnachweis")
    check(
        receipt_summary["used_as_lexical_input"] is False,
        "Manager-Archiv nicht als lexikalische Eingabe verwendet",
    )
    check(
        sha256(MANAGER_RECEIPTS) == receipt_summary["receipt_export_sha256"],
        "Manager-Empfangsexport-Hash",
    )

    alerts = read_jsonl(ALERTS)
    check(len(alerts) == 88, "88 Wazuh-Standardregel-Alarme")
    alert_ids = []
    for alert in alerts:
        text = alert["data"]["win"]["eventdata"]["scriptBlockText"]
        match = re.search(r"\$sampleId='(PST-\d{3})'", text)
        if match is None:
            raise AssertionError("Alarm ohne instrumentierte Testfall-ID")
        alert_ids.append(match.group(1))
    check(len(alert_ids) == len(set(alert_ids)) == 88, "88 eindeutige alarmierte Testfälle")

    run = read_json(RUN_SUMMARY)
    check(
        run["lexical_input_source"]
        == "Microsoft-Windows-PowerShell/Operational:4104/EventData/ScriptBlockText",
        "direkter Windows-Ereigniskanal als lexikalische Quelle",
    )
    check(
        run["event_channel_mapping"]["exact_dataset_scriptblock_match_count"] == 300,
        "300 im Hauptlauf exakt zugeordnete Ereignistexte",
    )
    check(run["alert_mapping"]["mapped_alert_count"] == 88, "88 zugeordnete Wazuh-Alarme")
    check(sha256(ALERTS) == run["alert_sha256"], "Wazuh-Alarmexport-Hash")


def verify_metric_row(row: dict[str, str]) -> None:
    tp, fp, tn, fn = (int(row[key]) for key in ("TP", "FP", "TN", "FN"))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    check(tp + fp + tn + fn == int(row["sample_count"]), f"{row['method']}: Konfusionsmatrix")
    check(close(float(row["precision"]), precision), f"{row['method']}: Precision")
    check(close(float(row["recall"]), recall), f"{row['method']}: Recall")
    check(close(float(row["fpr"]), fpr), f"{row['method']}: FPR")
    check(close(float(row["f1"]), f1), f"{row['method']}: F1-Score")


def verify_metrics() -> None:
    rows = read_csv(METRICS)
    check(
        {row["method"] for row in rows}
        == {"wazuh_standard", "lexical_pipeline", "hybrid_or", "hybrid_and"},
        "vier dokumentierte Hauptentscheidungen",
    )
    for row in rows:
        verify_metric_row(row)

    baseline = read_csv(BASELINE_METRICS)
    check(len(baseline) == 1, "eine Zeichen-n-Gramm-TF-IDF-Vergleichsbasis")
    verify_metric_row(baseline[0])
    check(
        baseline[0]["method"] == "char_ngram_tfidf_logistic_regression",
        "Bezeichnung der statistischen Vergleichsbasis",
    )


def verify_document_references() -> None:
    tex = TEX.read_text(encoding="utf-8")
    diagrams = re.findall(r"\\diagramfigure(?:\[[^\]]+\])?\{([^}]+)\}", tex)
    screenshots = re.findall(r"\\screenshotplaceholder\{([^}]+)\}", tex)

    for name in diagrams:
        check((ROOT / "figures" / name).is_file(), f"Diagramm vorhanden: {name}")
    for name in screenshots:
        check(
            (ROOT / "figures/screenshots" / name).is_file(),
            f"Screenshot vorhanden: {name}",
        )

    check("TODO" not in tex and "TBD" not in tex, "keine TODO- oder TBD-Markierungen")
    check("v5_1" not in tex and "final_thesis" not in tex, "keine veralteten Dateinamen")
    check(
        "Die 30 positiven Grundmuster sind direkt im Datensatzgenerator definiert."
        in tex,
        "eindeutige Sample-Provenienz in der Methodik",
    )
    generator = (ROOT / "artifacts/source/generate_dataset.py").read_text(
        encoding="utf-8"
    )
    check(
        "does not import complete scripts, C2 implants, or payload files" in generator,
        "eindeutige Sample-Provenienz im Generator",
    )


def main() -> None:
    verify_dataset()
    verify_event_and_wazuh_exports()
    verify_metrics()
    verify_document_references()
    print("\nRepository-Prüfung erfolgreich abgeschlossen.")


if __name__ == "__main__":
    main()
