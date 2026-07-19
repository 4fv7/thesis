#!/usr/bin/env python3
"""Generate the vector figures used by the ScriptBlockText evaluation."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch


BLUE = "#276FBF"
ORANGE = "#D66A1F"
GREEN = "#26835B"
RED = "#B23A48"
DARK = "#253341"
LIGHT = "#F7F8FA"
GRID = "#D7DDE3"


def setup_style() -> None:
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 9,
            "axes.edgecolor": DARK,
            "axes.labelcolor": DARK,
            "axes.grid": True,
            "grid.color": GRID,
            "grid.linewidth": 0.6,
            "grid.alpha": 0.9,
            "xtick.color": DARK,
            "ytick.color": DARK,
            "legend.frameon": False,
            "figure.facecolor": "white",
            "axes.facecolor": "white",
            "pdf.fonttype": 42,
        }
    )


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def save(fig: plt.Figure, path: Path) -> None:
    fig.savefig(path, bbox_inches="tight", pad_inches=0.05)
    plt.close(fig)


def box(ax, xy, width, height, title, body, color) -> None:
    patch = FancyBboxPatch(
        xy,
        width,
        height,
        boxstyle="round,pad=0.012,rounding_size=0.012",
        linewidth=1.2,
        edgecolor=color,
        facecolor=LIGHT,
    )
    ax.add_patch(patch)
    x, y = xy
    ax.text(
        x + 0.04 * width,
        y + 0.72 * height,
        title,
        color=DARK,
        fontsize=9.5,
        fontweight="bold",
        va="center",
    )
    ax.text(
        x + 0.04 * width,
        y + 0.36 * height,
        body,
        color=DARK,
        fontsize=8.2,
        va="center",
        linespacing=1.25,
    )


def arrow(ax, start, end) -> None:
    ax.add_patch(
        FancyArrowPatch(
            start,
            end,
            arrowstyle="-|>",
            mutation_scale=12,
            linewidth=1.15,
            color=DARK,
        )
    )


def architecture(out_dir: Path) -> None:
    fig, ax = plt.subplots(figsize=(10.4, 5.4))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    box(ax, (0.02, 0.74), 0.16, 0.17, "Datensatz", "300 PST-IDs\nLabels und Gruppen", GREEN)
    box(
        ax,
        (0.22, 0.74),
        0.18,
        0.17,
        "Windows-Ausführung",
        "PowerShell 5.1\nkontrollierter Lauf",
        BLUE,
    )
    box(
        ax,
        (0.45, 0.74),
        0.25,
        0.17,
        "Windows-Ereigniskanal",
        "PowerShell/Operational\nEvent-ID 4104",
        ORANGE,
    )
    box(
        ax,
        (0.04, 0.40),
        0.27,
        0.20,
        "Direkte lokale Erfassung",
        "JSONL-Export des ScriptBlockText\n300 eindeutig zugeordnete IDs",
        BLUE,
    )
    box(
        ax,
        (0.40, 0.40),
        0.25,
        0.20,
        "Wazuh-Agent und -Manager",
        "Weiterleitung desselben Kanals\nunveränderte Standardregeln",
        RED,
    )
    box(
        ax,
        (0.72, 0.40),
        0.25,
        0.20,
        "Manager-Archiv",
        "300 Ereignisse\nnur Transportnachweis",
        ORANGE,
    )
    box(
        ax,
        (0.04, 0.08),
        0.27,
        0.20,
        "Lexikalische Entscheidungen",
        "Punktemodell und TF-IDF\ndirekter lokaler 4104-Text",
        BLUE,
    )
    box(
        ax,
        (0.40, 0.08),
        0.25,
        0.20,
        "Gemeinsamer Vergleich",
        "identische PST-IDs und Labels\nMetriken und Teilgruppen",
        GREEN,
    )
    box(
        ax,
        (0.72, 0.08),
        0.25,
        0.20,
        "Wazuh-Entscheidungen",
        "88 Standardregel-Alarme\nsonst negativ bei Empfang",
        RED,
    )
    arrow(ax, (0.18, 0.825), (0.22, 0.825))
    arrow(ax, (0.40, 0.825), (0.45, 0.825))
    arrow(ax, (0.56, 0.74), (0.18, 0.60))
    arrow(ax, (0.59, 0.74), (0.525, 0.60))
    arrow(ax, (0.65, 0.50), (0.72, 0.50))
    arrow(ax, (0.175, 0.40), (0.175, 0.28))
    arrow(ax, (0.525, 0.40), (0.845, 0.28))
    arrow(ax, (0.31, 0.18), (0.40, 0.18))
    arrow(ax, (0.72, 0.18), (0.65, 0.18))
    save(fig, out_dir / "lab_architecture.pdf")

def experiment_flow(out_dir: Path) -> None:
    fig, ax = plt.subplots(figsize=(10.4, 4.8))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    box(
        ax,
        (0.02, 0.65),
        0.25,
        0.22,
        "1  Vorbereitung",
        "Datensatzprüfung\nAST-Sicherheitsprüfung",
        GREEN,
    )
    box(
        ax,
        (0.375, 0.65),
        0.25,
        0.22,
        "2  Ausführung",
        "300/300 Testfälle\nkontrolliert ausgeführt",
        BLUE,
    )
    box(
        ax,
        (0.73, 0.65),
        0.25,
        0.22,
        "3  Erfassung",
        "direkter Event-4104-Export\nund Wazuh-Weiterleitung",
        ORANGE,
    )
    box(
        ax,
        (0.02, 0.17),
        0.25,
        0.24,
        "4  Entscheidungen",
        "Wazuh, Punktemodell\nund Zeichen-n-Gramm-TF-IDF",
        RED,
    )
    box(
        ax,
        (0.375, 0.17),
        0.25,
        0.24,
        "5  Zuordnung",
        "identische PST-IDs, Labels\nund gruppierte Teilstichproben",
        BLUE,
    )
    box(
        ax,
        (0.73, 0.17),
        0.25,
        0.24,
        "6  Auswertung",
        "Metriken, Teilgruppen, Intervalle\nund isolierte Laufzeitmessung",
        GREEN,
    )
    arrow(ax, (0.27, 0.76), (0.375, 0.76))
    arrow(ax, (0.625, 0.76), (0.73, 0.76))
    arrow(ax, (0.855, 0.65), (0.145, 0.41))
    arrow(ax, (0.27, 0.29), (0.375, 0.29))
    arrow(ax, (0.625, 0.29), (0.73, 0.29))
    save(fig, out_dir / "experiment_flow.pdf")


def dataset_construction(out_dir: Path) -> None:
    """Explain which parts are source-informed and which parts are created locally."""

    fig, ax = plt.subplots(figsize=(10.4, 5.0))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    box(
        ax,
        (0.02, 0.68),
        0.25,
        0.21,
        "Fachliche Referenzen",
        "MITRE, Atomic, Sigma,\nLOLBAS und Wazuh\nnur konzeptionelle Grundlage",
        ORANGE,
    )
    box(
        ax,
        (0.36, 0.68),
        0.25,
        0.21,
        "30 positive Grundmuster",
        "im Rahmen der Arbeit definiert\ninert, keine vollständigen Payloads",
        BLUE,
    )
    box(
        ax,
        (0.70, 0.68),
        0.28,
        0.21,
        "150 positive Testfälle",
        "30 klare und 120 obfuskierte Fälle\nfünf Varianten je Verhaltensfamilie",
        RED,
    )
    box(
        ax,
        (0.02, 0.20),
        0.25,
        0.21,
        "Benigne Entwurfsbasis",
        "typische Administration\nund gezielt schwierige Grenzfälle",
        GREEN,
    )
    box(
        ax,
        (0.36, 0.20),
        0.25,
        0.21,
        "150 benigne Testfälle",
        "100 normale und 50 schwierige Fälle\nlokal zusammengestellt",
        BLUE,
    )
    box(
        ax,
        (0.70, 0.20),
        0.28,
        0.21,
        "Gesamtdatensatz",
        "300 synthetische Labortestfälle\nvom Verfasser gelabelt\nkeine reale Prävalenz",
        GREEN,
    )
    arrow(ax, (0.27, 0.785), (0.36, 0.785))
    arrow(ax, (0.61, 0.785), (0.70, 0.785))
    arrow(ax, (0.27, 0.305), (0.36, 0.305))
    arrow(ax, (0.61, 0.305), (0.70, 0.305))
    arrow(ax, (0.84, 0.68), (0.84, 0.41))
    save(fig, out_dir / "dataset_construction.pdf")


def event_channel_evidence(path: Path, out_dir: Path) -> None:
    """Show how one direct Event 4104 record becomes lexical input."""

    with path.open(encoding="utf-8") as handle:
        event = json.loads(next(line for line in handle if line.strip()))
    sample_id = str(event.get("sample_id", "PST-ID"))
    channel = str(
        event.get("channel", "Microsoft-Windows-PowerShell/Operational")
    )
    provider = str(
        event.get("provider_name", "Microsoft-Windows-PowerShell")
    )

    fig, ax = plt.subplots(figsize=(10.4, 4.2))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    box(
        ax,
        (0.03, 0.62),
        0.26,
        0.23,
        "Windows-Ereigniskanal",
        "PowerShell/Operational\nEvent-ID 4104",
        ORANGE,
    )
    box(
        ax,
        (0.37, 0.62),
        0.26,
        0.23,
        "Direkt erfasstes Feld",
        "EventData/ScriptBlockText\nEindeutige PST-ID",
        BLUE,
    )
    box(
        ax,
        (0.71, 0.62),
        0.26,
        0.23,
        "Python-Pipeline",
        "Merkmale, Punktwert\nund Klassifikation",
        GREEN,
    )
    arrow(ax, (0.29, 0.735), (0.37, 0.735))
    arrow(ax, (0.63, 0.735), (0.71, 0.735))

    panel = FancyBboxPatch(
        (0.03, 0.10),
        0.94,
        0.34,
        boxstyle="round,pad=0.012,rounding_size=0.012",
        linewidth=1.2,
        edgecolor=BLUE,
        facecolor=LIGHT,
    )
    ax.add_patch(panel)
    ax.text(
        0.055,
        0.385,
        "Beispiel eines direkt erfassten Event-4104-Datensatzes",
        color=DARK,
        fontsize=9.5,
        fontweight="bold",
        va="top",
    )
    lines = [
        f'channel              = "{channel}"',
        f'provider             = "{provider}"',
        f'event_id / record_id = {event.get("event_id", 4104)} / {event.get("record_id", "")}',
        f"script_block_text    = $sampleId='{sample_id}'; ...",
    ]
    ax.text(
        0.06,
        0.30,
        "\n".join(lines),
        color=DARK,
        fontsize=8.8,
        family="DejaVu Sans Mono",
        va="top",
        linespacing=1.35,
    )
    save(fig, out_dir / "windows_event_channel_evidence.pdf")


def threshold_chart(path: Path, out_dir: Path) -> None:
    rows = [row for row in read_csv(path) if int(row["threshold"]) <= 16]
    rows.sort(key=lambda row: int(row["threshold"]))
    x = [int(row["threshold"]) for row in rows]
    series = [
        ("Precision", "precision", BLUE, "o"),
        ("Recall", "recall", ORANGE, "s"),
        ("F1-Score", "f1", GREEN, "^"),
        ("FPR", "fpr", RED, "D"),
    ]
    fig, ax = plt.subplots(figsize=(9.5, 4.8))
    for label, field, color, marker in series:
        values = [float(row[field]) if row[field] else float("nan") for row in rows]
        ax.plot(
            x,
            values,
            label=label,
            color=color,
            marker=marker,
            linewidth=1.7,
            markersize=4,
        )
    ax.axvline(5, color=DARK, linestyle="--", linewidth=1.1)
    ax.text(
        5.35,
        0.56,
        "Einsatzwert: 5",
        ha="left",
        va="center",
        color=DARK,
        fontsize=8.5,
        bbox={
            "boxstyle": "square,pad=0.28",
            "facecolor": "white",
            "edgecolor": DARK,
            "linewidth": 0.7,
        },
    )
    ax.set_xlabel("Schwellenwert")
    ax.set_ylabel("Metrikwert")
    ax.set_xticks(x)
    ax.set_ylim(0, 1.04)
    ax.legend(ncol=4, loc="lower center", bbox_to_anchor=(0.5, -0.30))
    fig.subplots_adjust(bottom=0.24)
    save(fig, out_dir / "threshold_tradeoff.pdf")


def obfuscation_chart(path: Path, out_dir: Path) -> None:
    rows = read_csv(path)
    order = [
        ("Base64", "base64_literal_decode_safe"),
        ("String-\nkonkatenation", "string_concatenation"),
        ("Backticks", "backtick_literal"),
        ("Gemischte\nSchreibweise", "mixed_case"),
        ("Alias /\nRekonstruktion", "alias_command_reconstruction"),
        ("Kombinierte\nObfuskation", "combined_obfuscation"),
    ]
    lookup = {
        (row["method"], row["group_value"]): float(row["recall"])
        for row in rows
        if row["recall"]
    }
    x = list(range(len(order)))
    width = 0.36
    fig, ax = plt.subplots(figsize=(9.7, 5.0))
    wazuh = [lookup[("wazuh_standard", key)] for _, key in order]
    lexical = [lookup[("lexical_pipeline", key)] for _, key in order]
    bars1 = ax.bar([value - width / 2 for value in x], wazuh, width, label="Wazuh", color=BLUE)
    bars2 = ax.bar([value + width / 2 for value in x], lexical, width, label="Lexikalisch", color=ORANGE)
    ax.bar_label(bars1, fmt="%.2f", padding=2, fontsize=7.5)
    ax.bar_label(bars2, fmt="%.2f", padding=2, fontsize=7.5)
    ax.set_xticks(x, [label for label, _ in order])
    ax.set_ylabel("Recall")
    ax.set_ylim(0, 1.10)
    ax.legend(ncol=2, loc="upper center", bbox_to_anchor=(0.5, 1.13))
    save(fig, out_dir / "obfuscation_recall.pdf")


def confidence_interval_chart(path: Path, out_dir: Path) -> None:
    rows = read_csv(path)
    names = {
        "wazuh_standard": "Wazuh",
        "lexical_pipeline": "Lexikalisch",
        "hybrid_or": "ODER",
        "hybrid_and": "UND",
    }
    colors = {
        "wazuh_standard": BLUE,
        "lexical_pipeline": ORANGE,
        "hybrid_or": GREEN,
        "hybrid_and": RED,
    }
    methods = list(names)
    by_key = {(row["method"], row["metric"]): row for row in rows}
    fig, axes = plt.subplots(1, 2, figsize=(9.5, 4.4), sharey=True)
    for ax, metric, title in zip(axes, ("f1", "fpr"), ("F1-Score", "False-Positive-Rate")):
        for y, method in enumerate(methods):
            row = by_key[(method, metric)]
            estimate = float(row["estimate"])
            lower = float(row["ci_lower_95"])
            upper = float(row["ci_upper_95"])
            ax.errorbar(
                estimate,
                y,
                xerr=[[estimate - lower], [upper - estimate]],
                fmt="o",
                color=colors[method],
                ecolor=colors[method],
                capsize=4,
                linewidth=1.5,
            )
        ax.set_title(title)
        ax.set_xlabel("Schätzung und 95-%-Konfidenzintervall")
        ax.set_xlim(0, 1)
        ax.set_yticks(range(len(methods)), [names[method] for method in methods])
        ax.grid(axis="x")
        ax.grid(axis="y", visible=False)
    save(fig, out_dir / "bootstrap_confidence_intervals.pdf")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--analysis-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    setup_style()
    architecture(args.out_dir)
    experiment_flow(args.out_dir)
    dataset_construction(args.out_dir)
    event_channel_evidence(
        args.analysis_dir.parent / "local_event4104_dataset_run.jsonl",
        args.out_dir,
    )
    threshold_chart(args.analysis_dir / "threshold_tuning_full.csv", args.out_dir)
    obfuscation_chart(args.analysis_dir / "metrics_by_obfuscation.csv", args.out_dir)
    confidence_interval_chart(
        args.analysis_dir / "metrics_confidence_intervals.csv", args.out_dir
    )
    print(f"Generated figures in {args.out_dir}")


if __name__ == "__main__":
    main()
