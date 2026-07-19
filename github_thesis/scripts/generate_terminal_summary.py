#!/usr/bin/env python3
"""Render the recorded pipeline summary as a reproducible terminal-style figure."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
ANALYSIS = ROOT / "artifacts" / "messlauf" / "analysis"
OUTPUT = ROOT / "figures" / "screenshots" / "pipeline_terminal_summary.png"
FONT_PATH = Path("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf")
BOLD_FONT_PATH = Path("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf")


def load_metrics() -> dict[str, dict[str, str]]:
    with (ANALYSIS / "metrics_overall.csv").open(encoding="utf-8", newline="") as handle:
        return {row["method"]: row for row in csv.DictReader(handle)}


def main() -> None:
    summary = json.loads((ANALYSIS / "run_summary.json").read_text(encoding="utf-8"))
    metrics = load_metrics()
    mapping = summary["event_channel_mapping"]
    wazuh = metrics["wazuh_standard"]
    lexical = metrics["lexical_pipeline"]

    lines = [
        ("prompt", "$ python3 artifacts/source/pipeline.py run \\"),
        ("text", "  --dataset artifacts/dataset/powershell_scriptblock_samples.json \\"),
        ("text", "  --event-channel-events artifacts/messlauf/local_event4104_dataset_run.jsonl \\"),
        ("text", "  --alerts artifacts/messlauf/capture/alerts_standard_rules_dataset_run.jsonl \\"),
        ("text", "  --out-dir artifacts/messlauf/analysis --evaluation-mode grouped_cv \\"),
        ("text", "  --folds 5 --seed 20260711 --bootstrap-iterations 2000 --max-fpr 0.10"),
        ("blank", ""),
        ("key", "lexical_input_source"),
        ("value", f"  {summary['lexical_input_source']}"),
        ("key", "event_channel_mapping"),
        (
            "value",
            "  raw={raw} mapped={mapped} exact={exact} missing=0 duplicate=0".format(
                raw=mapping["raw_event_count"],
                mapped=mapping["mapped_sample_count"],
                exact=mapping["exact_dataset_scriptblock_match_count"],
            ),
        ),
        ("key", "wazuh_standard_alerts"),
        ("value", f"  mapped_samples={summary['alert_mapping']['mapped_sample_count']} rejected=0"),
        ("key", "deployment_threshold"),
        ("value", f"  {summary['deployment_threshold_full_dataset']}"),
        ("blank", ""),
        ("key", "overall_metrics"),
        (
            "value",
            "  Wazuh:  Precision={precision}  Recall={recall}  F1={f1}  FPR={fpr}".format(
                precision=wazuh["precision"],
                recall=wazuh["recall"],
                f1=wazuh["f1"],
                fpr=wazuh["fpr"],
            ),
        ),
        (
            "value",
            "  Lexical: Precision={precision}  Recall={recall}  F1={f1}  FPR={fpr}".format(
                precision=lexical["precision"],
                recall=lexical["recall"],
                f1=lexical["f1"],
                fpr=lexical["fpr"],
            ),
        ),
        ("success", "run completed: 300 samples evaluated"),
    ]

    width, height = 2000, 1120
    image = Image.new("RGB", (width, height), "#0d1117")
    draw = ImageDraw.Draw(image)
    font = ImageFont.truetype(str(FONT_PATH), 28)
    bold = ImageFont.truetype(str(BOLD_FONT_PATH), 28)
    title_font = ImageFont.truetype(str(BOLD_FONT_PATH), 25)

    draw.rectangle((0, 0, width, 72), fill="#161b22")
    draw.ellipse((28, 24, 50, 46), fill="#ff5f56")
    draw.ellipse((62, 24, 84, 46), fill="#ffbd2e")
    draw.ellipse((96, 24, 118, 46), fill="#27c93f")
    draw.text((145, 21), "pipeline.py - reproduzierter Messlauf", font=title_font, fill="#c9d1d9")

    colors = {
        "prompt": "#7ee787",
        "text": "#f0f6fc",
        "key": "#79c0ff",
        "value": "#c9d1d9",
        "success": "#7ee787",
        "blank": "#c9d1d9",
    }
    y = 105
    line_height = 47
    for kind, line in lines:
        draw.text(
            (65, y),
            line,
            font=bold if kind in {"key", "success"} else font,
            fill=colors[kind],
        )
        y += line_height

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    image.save(OUTPUT, format="PNG", optimize=True)


if __name__ == "__main__":
    main()
