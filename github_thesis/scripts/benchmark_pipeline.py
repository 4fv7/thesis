#!/usr/bin/env python3
"""Benchmark feature extraction and scoring of the lexical detector."""

from __future__ import annotations

import argparse
import csv
import gc
import importlib.util
import json
import os
import platform
import statistics
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


def load_pipeline(path: Path) -> Any:
    specification = importlib.util.spec_from_file_location("measured_pipeline", path)
    if specification is None or specification.loader is None:
        raise ImportError(f"Cannot load {path}")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def percentile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * probability)))
    return ordered[index]


def benchmark_batch(
    pipeline: Any,
    source_texts: list[str],
    operation_count: int,
) -> dict[str, object]:
    texts = [source_texts[index % len(source_texts)] for index in range(operation_count)]
    gc.collect()
    tracemalloc.start()
    start_cpu = time.process_time()
    start_wall = time.perf_counter()
    latencies_ms: list[float] = []
    score_checksum = 0

    for text in texts:
        start_item = time.perf_counter_ns()
        features = pipeline.extract_features(text)
        score, reasons = pipeline.lexical_score(features)
        score_checksum += score + len(reasons)
        latencies_ms.append((time.perf_counter_ns() - start_item) / 1_000_000.0)

    wall_seconds = time.perf_counter() - start_wall
    cpu_seconds = time.process_time() - start_cpu
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return {
        "operation_count": operation_count,
        "wall_seconds": round(wall_seconds, 6),
        "cpu_seconds": round(cpu_seconds, 6),
        "throughput_events_per_second": round(operation_count / wall_seconds, 2),
        "mean_latency_ms": round(statistics.fmean(latencies_ms), 4),
        "median_latency_ms": round(statistics.median(latencies_ms), 4),
        "p95_latency_ms": round(percentile(latencies_ms, 0.95), 4),
        "p99_latency_ms": round(percentile(latencies_ms, 0.99), 4),
        "peak_python_memory_mib": round(peak_bytes / (1024 * 1024), 3),
        "score_checksum": score_checksum,
    }


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def render_figure(rows: list[dict[str, object]], output_path: Path) -> None:
    counts = [int(row["operation_count"]) for row in rows]
    throughput = [float(row["throughput_events_per_second"]) for row in rows]
    median = [float(row["median_latency_ms"]) for row in rows]
    p95 = [float(row["p95_latency_ms"]) for row in rows]

    fig, axes = plt.subplots(1, 2, figsize=(10.4, 4.0))
    axes[0].plot(counts, throughput, marker="o", color="#3b6fb6", linewidth=2)
    axes[0].set_xlabel("Anzahl verarbeiteter ScriptBlocks")
    axes[0].set_ylabel("ScriptBlocks pro Sekunde")
    axes[0].grid(alpha=0.25)

    axes[1].plot(counts, median, marker="o", label="Median", color="#248f6b", linewidth=2)
    axes[1].plot(counts, p95, marker="s", label="95. Perzentil", color="#d97724", linewidth=2)
    axes[1].set_xlabel("Anzahl verarbeiteter ScriptBlocks")
    axes[1].set_ylabel("Latenz je ScriptBlock in ms")
    axes[1].grid(alpha=0.25)
    axes[1].legend(frameon=False)

    fig.tight_layout()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, format="pdf", bbox_inches="tight")
    plt.close(fig)


def run(args: argparse.Namespace) -> None:
    pipeline = load_pipeline(args.pipeline)
    with args.sample_results.open(encoding="utf-8", newline="") as handle:
        source_rows = list(csv.DictReader(handle))
    source_texts = [row["analysis_text"] for row in source_rows]
    if len(source_texts) != 300 or any(not text for text in source_texts):
        raise ValueError("Expected 300 non-empty measured ScriptBlock texts")

    for text in source_texts:
        pipeline.lexical_score(pipeline.extract_features(text))

    rows = [
        benchmark_batch(pipeline, source_texts, operation_count)
        for operation_count in args.operation_counts
    ]
    write_csv(args.output_csv, rows)
    render_figure(rows, args.figure_output)

    summary = {
        "scope": (
            "single-process CPU microbenchmark of feature extraction and lexical "
            "scoring; excludes event collection, JSON parsing, Wazuh, storage and network I/O"
        ),
        "source_sample_count": len(source_texts),
        "operation_counts": args.operation_counts,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "logical_cpu_count": os.cpu_count(),
        "results": rows,
    }
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2, ensure_ascii=False))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pipeline", type=Path, required=True)
    parser.add_argument("--sample-results", type=Path, required=True)
    parser.add_argument("--output-csv", type=Path, required=True)
    parser.add_argument("--output-json", type=Path, required=True)
    parser.add_argument("--figure-output", type=Path, required=True)
    parser.add_argument(
        "--operation-counts",
        type=int,
        nargs="+",
        default=[300, 1500, 3000],
    )
    return parser


if __name__ == "__main__":
    run(build_parser().parse_args())
