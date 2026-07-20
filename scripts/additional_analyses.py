#!/usr/bin/env python3
"""Run an established character n-gram TF-IDF logistic-regression baseline."""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Iterable

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import scipy
from scipy import sparse
from scipy.optimize import minimize
from scipy.special import expit


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        raise ValueError(f"No rows for {path}")
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


VARIABLE_RE = re.compile(r"\$[A-Za-z_][A-Za-z0-9_:]*")
WRITE_OUTPUT_VARIABLE_RE = re.compile(r"(?i)\bwrite-output\s+\$var\b\s*;?")
ASSIGNMENT_RE = re.compile(r"\$var\s*=\s*")


def normalize_for_baseline(text: str) -> str:
    normalized = text.casefold().replace("\r\n", "\n").replace("\r", "\n")
    normalized = VARIABLE_RE.sub("$var", normalized)
    normalized = WRITE_OUTPUT_VARIABLE_RE.sub(" ", normalized)
    normalized = ASSIGNMENT_RE.sub(" ", normalized)
    normalized = normalized.replace("$var", " var ")
    return re.sub(r"\s+", " ", normalized).strip()


def ngrams(text: str, min_n: int, max_n: int) -> Iterable[str]:
    normalized = normalize_for_baseline(text)
    for size in range(min_n, max_n + 1):
        stop = len(normalized) - size + 1
        for index in range(max(0, stop)):
            yield normalized[index : index + size]


def build_vocabulary(
    texts: list[str],
    min_n: int,
    max_n: int,
    min_df: int,
    max_features: int,
) -> tuple[dict[str, int], np.ndarray]:
    document_frequency: Counter[str] = Counter()
    for text in texts:
        document_frequency.update(set(ngrams(text, min_n, max_n)))

    candidates = [
        (token, frequency)
        for token, frequency in document_frequency.items()
        if frequency >= min_df
    ]
    candidates.sort(key=lambda item: (-item[1], item[0]))
    selected = candidates[:max_features]
    vocabulary = {token: index for index, (token, _) in enumerate(selected)}
    idf = np.array(
        [math.log((1.0 + len(texts)) / (1.0 + frequency)) + 1.0 for _, frequency in selected],
        dtype=np.float64,
    )
    return vocabulary, idf


def transform(
    texts: list[str],
    vocabulary: dict[str, int],
    idf: np.ndarray,
    min_n: int,
    max_n: int,
) -> sparse.csr_matrix:
    data: list[float] = []
    indices: list[int] = []
    indptr = [0]

    for text in texts:
        counts: Counter[int] = Counter()
        for token in ngrams(text, min_n, max_n):
            feature_index = vocabulary.get(token)
            if feature_index is not None:
                counts[feature_index] += 1

        norm = math.sqrt(
            sum((count * float(idf[index])) ** 2 for index, count in counts.items())
        )
        if norm:
            for index in sorted(counts):
                indices.append(index)
                data.append((counts[index] * float(idf[index])) / norm)
        indptr.append(len(data))

    return sparse.csr_matrix(
        (
            np.asarray(data, dtype=np.float64),
            np.asarray(indices, dtype=np.int32),
            np.asarray(indptr, dtype=np.int32),
        ),
        shape=(len(texts), len(vocabulary)),
    )


def fit_logistic_regression(
    matrix: sparse.csr_matrix,
    labels: np.ndarray,
    regularization: float,
    max_iterations: int,
) -> tuple[np.ndarray, float, dict[str, object]]:
    feature_count = matrix.shape[1]
    initial = np.zeros(feature_count + 1, dtype=np.float64)

    def objective(parameters: np.ndarray) -> tuple[float, np.ndarray]:
        weights = parameters[:-1]
        intercept = parameters[-1]
        logits = matrix @ weights + intercept
        residual = expit(logits) - labels
        loss = float(
            np.logaddexp(0.0, logits).sum()
            - np.dot(labels, logits)
            + 0.5 * regularization * np.dot(weights, weights)
        )
        gradient_weights = np.asarray(matrix.T @ residual).ravel()
        gradient_weights += regularization * weights
        gradient = np.concatenate((gradient_weights, np.array([residual.sum()])))
        return loss, gradient

    result = minimize(
        objective,
        initial,
        method="L-BFGS-B",
        jac=True,
        options={"maxiter": max_iterations, "ftol": 1e-10, "gtol": 1e-6},
    )
    diagnostics = {
        "converged": bool(result.success),
        "iterations": int(result.nit),
        "final_objective": float(result.fun),
        "message": str(result.message),
    }
    return result.x[:-1], float(result.x[-1]), diagnostics


def confusion_metrics(truth: list[int], predictions: list[int]) -> dict[str, object]:
    tp = sum(1 for y, p in zip(truth, predictions) if y == 1 and p == 1)
    fp = sum(1 for y, p in zip(truth, predictions) if y == 0 and p == 1)
    tn = sum(1 for y, p in zip(truth, predictions) if y == 0 and p == 0)
    fn = sum(1 for y, p in zip(truth, predictions) if y == 1 and p == 0)

    def ratio(numerator: int, denominator: int) -> float:
        return numerator / denominator if denominator else 0.0

    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    f1 = ratio(2.0 * precision * recall, precision + recall)
    fpr = ratio(fp, fp + tn)
    specificity = ratio(tn, tn + fp)
    accuracy = ratio(tp + tn, tp + fp + tn + fn)
    return {
        "sample_count": len(truth),
        "positive_count": sum(truth),
        "negative_count": len(truth) - sum(truth),
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "fpr": round(fpr, 6),
        "specificity": round(specificity, 6),
        "accuracy": round(accuracy, 6),
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
    }


def grouped_metrics(
    rows: list[dict[str, object]],
    field: str,
    method: str,
) -> list[dict[str, object]]:
    values = sorted({str(row[field]) for row in rows})
    result: list[dict[str, object]] = []
    for value in values:
        selected = [row for row in rows if str(row[field]) == value]
        metrics = confusion_metrics(
            [int(row["truth"]) for row in selected],
            [int(row["prediction"]) for row in selected],
        )
        result.append(
            {
                "method": method,
                "group_field": field,
                "group_value": value,
                **metrics,
            }
        )
    return result


def render_comparison(
    overall_metrics_path: Path,
    baseline_metrics: dict[str, object],
    output_path: Path,
) -> None:
    existing = {
        row["method"]: row for row in read_csv(overall_metrics_path)
    }
    methods = [
        ("Wazuh-Standardregeln", existing["wazuh_standard"]),
        ("Lexikalisches Punktmodell", existing["lexical_pipeline"]),
        ("TF-IDF + logistische Regression", baseline_metrics),
    ]
    metric_keys = ["precision", "recall", "f1", "fpr"]
    labels = ["Precision", "Recall", "F1-Score", "FPR"]
    colors = ["#3b6fb6", "#248f6b", "#d97724"]
    x = np.arange(len(metric_keys))
    width = 0.24

    fig, axis = plt.subplots(figsize=(10.4, 4.8))
    for index, (name, values) in enumerate(methods):
        heights = [float(values[key]) for key in metric_keys]
        bars = axis.bar(
            x + (index - 1) * width,
            heights,
            width,
            label=name,
            color=colors[index],
        )
        axis.bar_label(bars, labels=[f"{value:.2f}" for value in heights], padding=2, fontsize=8)

    axis.set_xticks(x, labels)
    axis.set_ylim(0.0, 1.08)
    axis.set_ylabel("Metrikwert")
    axis.grid(axis="y", alpha=0.25, linewidth=0.7)
    axis.legend(loc="upper center", bbox_to_anchor=(0.5, -0.13), ncol=3, frameon=False)
    fig.tight_layout()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, format="pdf", bbox_inches="tight")
    plt.close(fig)


def run(args: argparse.Namespace) -> None:
    rows = read_csv(args.sample_results)
    if len(rows) != 300:
        raise ValueError(f"Expected 300 sample rows, got {len(rows)}")
    if any(not row.get("analysis_text") for row in rows):
        raise ValueError("Missing analysis_text")
    if any(row.get("cv_fold", "") == "" for row in rows):
        raise ValueError("Missing cv_fold")

    fold_ids = sorted({int(row["cv_fold"]) for row in rows})
    all_predictions: dict[str, dict[str, object]] = {}
    fold_metrics: list[dict[str, object]] = []
    fold_diagnostics: list[dict[str, object]] = []

    for fold in fold_ids:
        training_rows = [row for row in rows if int(row["cv_fold"]) != fold]
        test_rows = [row for row in rows if int(row["cv_fold"]) == fold]
        training_texts = [row["analysis_text"] for row in training_rows]
        test_texts = [row["analysis_text"] for row in test_rows]
        training_labels = np.asarray(
            [int(row["truth"]) for row in training_rows], dtype=np.float64
        )
        test_labels = [int(row["truth"]) for row in test_rows]

        vocabulary, idf = build_vocabulary(
            training_texts,
            args.min_ngram,
            args.max_ngram,
            args.min_df,
            args.max_features,
        )
        training_matrix = transform(
            training_texts,
            vocabulary,
            idf,
            args.min_ngram,
            args.max_ngram,
        )
        test_matrix = transform(
            test_texts,
            vocabulary,
            idf,
            args.min_ngram,
            args.max_ngram,
        )
        weights, intercept, diagnostics = fit_logistic_regression(
            training_matrix,
            training_labels,
            args.regularization,
            args.max_iterations,
        )
        probabilities = expit(test_matrix @ weights + intercept)
        predictions = (probabilities >= 0.5).astype(int).tolist()

        metrics = confusion_metrics(test_labels, predictions)
        fold_metrics.append({"fold": fold, **metrics})
        fold_diagnostics.append(
            {
                "fold": fold,
                "training_sample_count": len(training_rows),
                "test_sample_count": len(test_rows),
                "vocabulary_size": len(vocabulary),
                **diagnostics,
            }
        )
        for row, probability, prediction in zip(test_rows, probabilities, predictions):
            all_predictions[row["id"]] = {
                "id": row["id"],
                "cv_fold": fold,
                "truth": int(row["truth"]),
                "dataset_group": row["dataset_group"],
                "obfuscation_type": row["obfuscation_type"],
                "behavior_family": row["behavior_family"],
                "probability": round(float(probability), 8),
                "prediction": int(prediction),
            }

    if set(all_predictions) != {row["id"] for row in rows}:
        raise ValueError("Out-of-fold predictions are incomplete")

    ordered_predictions = [all_predictions[row["id"]] for row in rows]
    overall = confusion_metrics(
        [int(row["truth"]) for row in ordered_predictions],
        [int(row["prediction"]) for row in ordered_predictions],
    )
    overall_row = {
        "method": "char_ngram_tfidf_logistic_regression",
        "group_field": "all",
        "group_value": "all",
        **overall,
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.output_dir / "char_ngram_baseline_predictions.csv", ordered_predictions)
    write_csv(args.output_dir / "char_ngram_baseline_metrics.csv", [overall_row])
    write_csv(args.output_dir / "char_ngram_baseline_folds.csv", fold_metrics)
    write_csv(args.output_dir / "char_ngram_baseline_diagnostics.csv", fold_diagnostics)
    write_csv(
        args.output_dir / "char_ngram_baseline_by_dataset_group.csv",
        grouped_metrics(
            ordered_predictions,
            "dataset_group",
            "char_ngram_tfidf_logistic_regression",
        ),
    )
    positive_predictions = [row for row in ordered_predictions if int(row["truth"]) == 1]
    write_csv(
        args.output_dir / "char_ngram_baseline_by_obfuscation.csv",
        grouped_metrics(
            positive_predictions,
            "obfuscation_type",
            "char_ngram_tfidf_logistic_regression",
        ),
    )

    summary = {
        "method": "character 3-5 gram TF-IDF with L2 logistic regression",
        "input": "directly captured and de-instrumented Event ID 4104 ScriptBlockText",
        "fold_source": "same grouped five-fold assignment as the lexical point model",
        "decision_threshold": 0.5,
        "scaffold_normalization": (
            "case folding, variable-name normalization, removal of variable "
            "assignments and trailing Write-Output variable wrappers"
        ),
        "min_ngram": args.min_ngram,
        "max_ngram": args.max_ngram,
        "min_document_frequency": args.min_df,
        "max_features": args.max_features,
        "l2_regularization": args.regularization,
        "numpy_version": np.__version__,
        "scipy_version": scipy.__version__,
        "overall_metrics": overall_row,
        "fold_diagnostics": fold_diagnostics,
    }
    (args.output_dir / "char_ngram_baseline_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    render_comparison(
        args.overall_metrics,
        overall_row,
        args.figure_output,
    )
    print(json.dumps(summary, indent=2, ensure_ascii=False))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample-results", type=Path, required=True)
    parser.add_argument("--overall-metrics", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--figure-output", type=Path, required=True)
    parser.add_argument("--min-ngram", type=int, default=3)
    parser.add_argument("--max-ngram", type=int, default=5)
    parser.add_argument("--min-df", type=int, default=2)
    parser.add_argument("--max-features", type=int, default=15000)
    parser.add_argument("--regularization", type=float, default=1.0)
    parser.add_argument("--max-iterations", type=int, default=250)
    return parser


if __name__ == "__main__":
    run(build_parser().parse_args())

