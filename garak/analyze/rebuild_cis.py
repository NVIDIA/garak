# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Standalone tool to recalculate confidence intervals for an existing garak report.

Usage:
    python -m garak.analyze.rebuild_cis -r path/to/report.jsonl
    python -m garak.analyze.rebuild_cis -r report.jsonl -w
    python -m garak.analyze.rebuild_cis -r report.jsonl -o rebuilt.jsonl
    python -m garak.analyze.rebuild_cis -r report.jsonl --bootstrap_confidence_level 0.99
"""

import logging
import sys
from pathlib import Path
from typing import Optional

from garak import _config
from garak.exception import GarakException


def _resolve_output_path(
    report_file: Path,
    output_path: Optional[str],
    overwrite: bool,
) -> Optional[str]:
    """Resolve the output file path based on flags.

    Returns None when overwrite is True (signals in-place update),
    otherwise returns the resolved output path string.
    """
    if overwrite:
        return None
    if output_path:
        return str(Path(output_path))

    name = report_file.name
    if name.endswith(".report.jsonl"):
        new_name = name.removesuffix(".report.jsonl") + ".rebuilt.report.jsonl"
    else:
        new_name = f"{report_file.stem}.rebuilt{report_file.suffix}"
    return str(report_file.parent / new_name)


def rebuild_cis_for_report(
    report_path: str,
    output_path: Optional[str] = None,
    overwrite: bool = False,
) -> int:
    """Rebuild CIs for an existing report using the active CI method.

    Reads all parameters from _config (already resolved via CLI > --config > site.yaml > core.yaml).
    Returns 0 on success, 1 on error.
    """
    if not _config.loaded:
        _config.load_config()

    if output_path and overwrite:
        print("❌ --output_path and --overwrite are mutually exclusive.")
        return 1

    report_file = Path(report_path)

    if not report_file.exists():
        msg = f"Report file not found: {report_file}"
        logging.critical(msg)
        raise GarakException(msg)

    if not report_file.is_file():
        print(f"❌ Path is not a file: {report_file}")
        return 1

    ci_method = _config.reporting.confidence_interval_method
    if ci_method != "bootstrap":
        print(f"❌ Unknown or disabled CI method: '{ci_method}'. Nothing to rebuild.")
        return 0

    from garak.analyze.ci_calculator import (
        _extract_ci_config_from_report,
        _extract_reporting_config_from_setup,
        calculate_ci_from_report,
        update_eval_entries_with_ci,
    )
    from garak.analyze.report_digest import append_report_object, build_digest

    resolved_output = _resolve_output_path(report_file, output_path, overwrite)
    if resolved_output:
        logging.info("Output will be written to: %s", resolved_output)
    else:
        logging.info("Report will be updated in-place: %s", report_file)

    original_reporting = _extract_reporting_config_from_setup(str(report_file))
    if original_reporting:
        active_reporting = {
            f"reporting.{p}": getattr(_config.reporting, p)
            for p in _config.reporting_params
        }
        diffs = {
            k: (original_reporting.get(k), v)
            for k, v in active_reporting.items()
            if original_reporting.get(k) != v
        }
        if diffs:
            for key, (old, new) in diffs.items():
                logging.info("Config changed: %s: %s -> %s", key, old, new)

    existing = _extract_ci_config_from_report(str(report_file))
    active_level = _config.reporting.bootstrap_confidence_level

    if existing:
        existing_method = existing.get("confidence_method", "unknown")
        existing_level = existing.get("confidence_level")
        if existing_method != ci_method:
            print(f"📊 Report used '{existing_method}' method. Rebuilding with '{ci_method}'.")
        if existing_level is not None and abs(existing_level - active_level) > 1e-9:
            print(
                f"📊 Report has existing CIs at {existing_level * 100:.1f}% confidence. "
                f"Rebuilding with {active_level * 100:.1f}% confidence."
            )
        else:
            print(f"📊 Rebuilding CIs at {active_level * 100:.1f}% confidence for {report_file}")
    else:
        print(
            f"📊 No existing CIs found in report. "
            f"Calculating with {ci_method} ({active_level * 100:.1f}% confidence)"
        )

    try:
        ci_results = calculate_ci_from_report(str(report_file))

        if len(ci_results) == 0:
            min_samples = _config.reporting.bootstrap_min_sample_size
            print(
                f"⚠️  No CIs calculated: all probe/detector pairs have "
                f"fewer than {min_samples} samples"
            )
            return 0

        print(f"📊 Updating {len(ci_results)} probe/detector pairs with new CIs")
        update_eval_entries_with_ci(
            str(report_file), ci_results, output_path=resolved_output
        )

        target_file = Path(resolved_output) if resolved_output else report_file
        digest = build_digest(str(target_file))
        with open(target_file, "a+", encoding="utf-8") as reportfile:
            append_report_object(reportfile, digest)
        logging.info("Recalculated digest appended to %s", target_file)

        print(f"✅ CIs recalculated and written to: {target_file}")

    except ValueError as e:
        print(f"❌ Invalid report data: {e}")
        return 1
    except OSError as e:
        print(f"❌ I/O error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    import argparse

    sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(
        description="Recalculate confidence intervals for an existing garak report.",
        prog="python -m garak.analyze.rebuild_cis",
        epilog="See https://github.com/NVIDIA/garak",
    )
    parser.add_argument(
        "--report_path",
        "-r",
        required=True,
        help="Path to the report JSONL file",
    )

    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument(
        "--output_path",
        "-o",
        help="Output path for the rebuilt report (default: {stem}.rebuilt.report.jsonl)",
    )
    output_group.add_argument(
        "--overwrite",
        "-w",
        action="store_true",
        help="Overwrite the input report file in-place",
    )

    parser.add_argument(
        "--confidence_interval_method",
        type=str,
        default=None,
        choices=["bootstrap", "none"],
        help="CI method: 'bootstrap' (default) or 'none' to disable",
    )
    parser.add_argument(
        "--bootstrap_num_iterations",
        type=int,
        default=None,
        help="Number of bootstrap iterations (overrides config)",
    )
    parser.add_argument(
        "--bootstrap_confidence_level",
        type=float,
        default=None,
        help="Confidence level, e.g. 0.95 for 95%% (overrides config)",
    )
    parser.add_argument(
        "--bootstrap_min_sample_size",
        type=int,
        default=None,
        help="Minimum sample size for CI calculation (overrides config)",
    )

    args = parser.parse_args()

    _config.load_config()

    if hasattr(_config, "reporting"):
        for param in _config.reporting_params:
            cli_value = getattr(args, param, None)
            if cli_value is not None:
                setattr(_config.reporting, param, cli_value)

    result = rebuild_cis_for_report(
        report_path=args.report_path,
        output_path=args.output_path,
        overwrite=args.overwrite,
    )
    sys.exit(result)
