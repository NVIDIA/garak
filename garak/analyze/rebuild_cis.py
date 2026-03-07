# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Orchestrates --rebuild_cis: recalculate CIs for an existing report."""

import logging
from pathlib import Path

from garak import _config
from garak.exception import GarakException


def rebuild_cis_for_report(report_path: str) -> int:
    """Rebuild CIs for an existing report using the active CI method.

    Reads all parameters from _config (already resolved via CLI > --config > site.yaml > core.yaml).
    Returns 0 on success, 1 on error.
    """
    if not _config.loaded:
        _config.load_config()

    report_file = Path(report_path)

    if not report_file.exists():
        msg = f"❌ Report file not found: {report_file}"
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
        calculate_ci_from_report,
        update_eval_entries_with_ci,
    )

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
        update_eval_entries_with_ci(str(report_file), ci_results)

        print(f"✅ CIs recalculated and report updated: {report_file}")

        from garak.analyze.report_digest import build_digest, build_html

        digest = build_digest(str(report_file))
        html_output = report_file.with_suffix(".html")
        html_report = build_html(digest, _config)
        with open(html_output, "w", encoding="utf-8") as htmlfile:
            htmlfile.write(html_report)
        print(f"📄 HTML digest written to {html_output}")

    except ValueError as e:
        print(f"❌ Invalid report data: {e}")
        return 1
    except OSError as e:
        print(f"❌ I/O error: {e}")
        return 1

    return 0
