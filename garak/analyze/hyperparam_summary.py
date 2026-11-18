# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Post-run summary of HyperparamBasher inference parameter sweep results.

Reads a garak JSONL report and prints a per-parameter-combination table
showing attack success rates derived from the harness detector results.

Usage::

    python -m garak.analyze.hyperparam_summary --report /path/to/run.report.jsonl
"""

import argparse
import json
import pathlib
import sys
from collections import defaultdict


def summarise(report_path: pathlib.Path) -> None:
    """Print a per-combo attack success rate table from a garak JSONL report.

    Groups completed HyperparamBasher attempts by their ``hyperparam_combo``
    note and tallies detection scores (``>= 0.5`` = attack success / fail)
    from ``detector_results`` written by the harness after the probe run.
    """
    combo_stats: dict[str, dict[str, int]] = defaultdict(
        lambda: {"fail": 0, "total": 0}
    )
    found = 0
    no_results = 0

    with report_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if record.get("entry_type") != "attempt" or record.get("status") != 2:
                continue
            combo = record.get("notes", {}).get("hyperparam_combo")
            if combo is None:
                continue
            key = json.dumps(combo, sort_keys=True)
            detector_results: dict = record.get("detector_results", {})
            if not detector_results:
                no_results += 1
            for scores in detector_results.values():
                for score in scores:
                    combo_stats[key]["total"] += 1
                    if score >= 0.5:
                        combo_stats[key]["fail"] += 1
            found += 1

    if not found:
        print("No HyperparamBasher attempts found in report.")
        return

    if no_results == found:
        print(
            "Warning: no detector_results found in any attempt. "
            "Ensure the report was produced by a completed garak run."
        )

    print(f"\nHyperparamBasher — per-combo detection summary:")
    for key in sorted(combo_stats):
        stats = combo_stats[key]
        total = stats["total"]
        fail = stats["fail"]
        rate = 100 * fail / total if total else 0.0
        combo_repr = json.loads(key)
        print(
            f"  {combo_repr} → {fail}/{total} failed ({rate:.0f}% attack success rate)"
        )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="python -m garak.analyze.hyperparam_summary",
        description="Per-combo attack success rate summary for HyperparamBasher runs.",
        allow_abbrev=False,
    )
    parser.add_argument(
        "-r",
        "--report",
        required=True,
        help="Path to the garak JSONL report file",
    )
    args = parser.parse_args(argv)

    report_path = pathlib.Path(args.report)
    if not report_path.exists():
        print(f"Error: report file not found: {report_path}", file=sys.stderr)
        sys.exit(1)

    summarise(report_path)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
