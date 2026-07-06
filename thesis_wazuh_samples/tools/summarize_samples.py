#!/usr/bin/env python3
"""Print compact counts for the generated sample CSV."""

from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CSV_PATH = ROOT / "data" / "powershell_scriptblock_samples.csv"


def main() -> None:
    with CSV_PATH.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))

    print(f"total: {len(rows)}")
    for field in ["label", "source_family", "obfuscation_type", "safety_class"]:
        print(f"\n{field}")
        for key, value in sorted(Counter(row[field] for row in rows).items()):
            print(f"  {key}: {value}")


if __name__ == "__main__":
    main()
