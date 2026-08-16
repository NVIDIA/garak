# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import logging
from pathlib import Path
from typing import Optional, Dict, List, Tuple

from garak import _config
from garak.analyze.bootstrap_ci import (
    apply_detector_correction,
    calculate_bootstrap_ci,
)
from garak.analyze.detector_metrics import get_detector_metrics
from garak.analyze.wilson_ci import (
    calculate_wilson_ci,
    fallback_wilson_if_degenerate,
)


def _get_report_digest(report_path: str) -> Optional[dict]:
    """Extract digest entry from end of report JSONL"""
    with open(report_path, "r", encoding="utf-8") as reportfile:
        for entry in [json.loads(line.strip()) for line in reportfile if line.strip()]:
            if entry.get("entry_type") == "digest":
                return entry
    return None


def _extract_ci_config_from_report(report_path: str) -> dict:
    """Extract CI config from existing eval entries in report.

    Returns dict with keys 'confidence_method' and 'confidence_level'
    if found, empty dict if no CI data present.
    """
    with open(report_path, "r", encoding="utf-8") as reportfile:
        for line in reportfile:
            if not line.strip():
                continue
            entry = json.loads(line.strip())
            if entry.get("entry_type") == "eval" and "confidence" in entry:
                result = {}
                if "confidence_method" in entry:
                    result["confidence_method"] = entry["confidence_method"]
                try:
                    result["confidence_level"] = float(entry["confidence"])
                except (ValueError, TypeError):
                    pass
                if result:
                    return result
    return {}


def _extract_reporting_config_from_setup(report_path: str) -> dict:
    """Extract reporting.* config values from the start_run setup entry."""
    with open(report_path, "r", encoding="utf-8") as f:
        first_line = f.readline().strip()
        if not first_line:
            return {}
        entry = json.loads(first_line)
        if entry.get("entry_type") != "start_run setup":
            return {}
        return {
            k: v for k, v in entry.items()
            if k.startswith("reporting.")
        }


def _reconstruct_binary_from_aggregates(passed: int, failed: int) -> List[int]:
    # Reconstruct binary pass/fail data from aggregates; order irrelevant for bootstrap resampling
    return [1] * passed + [0] * failed


def calculate_ci_from_report(
    report_path: str,
    probe_detector_pairs: Optional[List[Tuple[str, str]]] = None,
    num_iterations: Optional[int] = None,
    confidence_level: Optional[float] = None,
    confidence_method: Optional[str] = None,
) -> Dict[Tuple[str, str], Tuple[float, float]]:
    """Calculate CIs for probe/detector pairs using report digest aggregates.

    The active method (bootstrap by default, or Wilson) is read from config
    unless overridden via ``confidence_method``. All intervals — including
    the Wilson fallback for degenerate bootstraps — are reported on the
    Se/Sp-corrected ASR scale so a rebuilt report mixes no estimands,
    matching the evaluator behavior.
    """
    ci_results, _ = calculate_ci_from_report_with_methods(
        report_path,
        probe_detector_pairs=probe_detector_pairs,
        num_iterations=num_iterations,
        confidence_level=confidence_level,
        confidence_method=confidence_method,
    )
    return ci_results


def calculate_ci_from_report_with_methods(
    report_path: str,
    probe_detector_pairs: Optional[List[Tuple[str, str]]] = None,
    num_iterations: Optional[int] = None,
    confidence_level: Optional[float] = None,
    confidence_method: Optional[str] = None,
) -> Tuple[Dict[Tuple[str, str], Tuple[float, float]], Dict[Tuple[str, str], str]]:
    """Calculate CIs, also returning the method used for each pair.

    Returns ``(ci_results, ci_methods)`` where ``ci_methods[key]`` is
    ``"bootstrap"`` or ``"wilson"`` for every pair in ``ci_results``.
    """
    report_file = Path(report_path)

    if not report_file.exists():
        raise FileNotFoundError(
            f"Report file not found at: {report_file}. "
            f"Expected to find garak report JSONL file."
        )

    # Pull defaults from config
    if num_iterations is None:
        num_iterations = _config.reporting.bootstrap_num_iterations
    if confidence_level is None:
        confidence_level = _config.reporting.bootstrap_confidence_level
    ci_method = confidence_method or _config.reporting.confidence_interval_method

    # Read digest entry from report
    digest = _get_report_digest(str(report_file))

    if digest is None:
        raise ValueError(
            f"Report {report_file} missing 'digest' entry. "
            f"Digest is required for CI calculation from aggregates. "
            f"Ensure report was generated with garak v0.11.0 or later."
        )

    eval_data = digest.get("eval", {})
    if not eval_data:
        logging.warning("No evaluation data found in digest for %s", report_file)
        return {}, {}

    # Load detector metrics for Se/Sp correction
    detector_metrics = get_detector_metrics()
    min_sample_size = _config.reporting.bootstrap_min_sample_size

    ci_results = {}
    ci_methods = {}

    # Iterate through digest structure: probe_group -> probe_class -> detector
    for probe_group in eval_data:
        for probe_key in eval_data[probe_group]:
            if probe_key == "_summary":
                continue

            # Parse probe module and class from key (format: "module.class")
            if "." not in probe_key:
                continue

            probe_name = probe_key

            for detector_key in eval_data[probe_group][probe_key]:
                if detector_key == "_summary":
                    continue

                detector_name = detector_key

                # Skip if not in requested pairs (if specified)
                if probe_detector_pairs is not None:
                    if (probe_name, detector_name) not in probe_detector_pairs:
                        continue

                detector_result = eval_data[probe_group][probe_key][detector_key]

                # Extract aggregates
                total = detector_result.get("total_evaluated", 0)
                passed = detector_result.get("passed", 0)

                if total == 0:
                    logging.warning(
                        "No evaluated samples for probe=%s, detector=%s",
                        probe_name,
                        detector_name,
                    )
                    continue

                # Check minimum sample size
                if total < min_sample_size:
                    logging.warning(
                        "Insufficient samples for CI calculation: probe=%s, detector=%s, n=%d (minimum: %d)",
                        probe_name,
                        detector_name,
                        total,
                        min_sample_size,
                    )
                    continue

                # Reconstruct binary data from aggregates
                # Order irrelevant: bootstrap resamples randomly with replacement
                failed = total - passed
                binary_results = _reconstruct_binary_from_aggregates(passed, failed)

                # Get detector Se/Sp for correction
                se, sp = detector_metrics.get_detector_se_sp(detector_key)

                if ci_method == "wilson":
                    ci_result = calculate_wilson_ci(
                        successes=failed,
                        n=total,
                        confidence_level=confidence_level,
                    )
                    if ci_result is not None:
                        # Report on the Se/Sp-corrected ASR scale so wilson
                        # and bootstrap rows share one estimand (#2033).
                        ci_result = apply_detector_correction(ci_result, se, sp)
                    method = "wilson" if ci_result is not None else None
                elif ci_method == "bootstrap":
                    ci_result = calculate_bootstrap_ci(
                        results=binary_results,
                        sensitivity=se,
                        specificity=sp,
                        num_iterations=num_iterations,
                        confidence_level=confidence_level,
                    )
                    if ci_result is not None:
                        ci_lower, ci_upper, method = fallback_wilson_if_degenerate(
                            ci_result[0],
                            ci_result[1],
                            successes=failed,
                            n=total,
                            confidence_level=confidence_level,
                            sensitivity=se,
                            specificity=sp,
                        )
                        ci_result = (ci_lower, ci_upper)
                else:
                    logging.warning(
                        "Unknown CI method '%s' for probe=%s, detector=%s",
                        ci_method,
                        probe_name,
                        detector_name,
                    )
                    continue

                if ci_result is not None and method is not None:
                    key = (probe_name, detector_name)
                    ci_results[key] = ci_result
                    ci_methods[key] = method
                    logging.debug(
                        "Calculated %s CI for %s / %s: [%.2f, %.2f] (n=%d)",
                        method,
                        probe_name,
                        detector_name,
                        ci_result[0],
                        ci_result[1],
                        total,
                    )

    return ci_results, ci_methods


def update_eval_entries_with_ci(
    report_path: str,
    ci_results: Dict[Tuple[str, str], Tuple[float, float]],
    output_path: Optional[str] = None,
    confidence_method: Optional[str] = None,
    confidence_level: Optional[float] = None,
    confidence_methods: Optional[Dict[Tuple[str, str], str]] = None,
) -> None:
    """Update eval entries in report JSONL with new CI values, overwrites if output_path is None"""
    if confidence_method is None:
        confidence_method = _config.reporting.confidence_interval_method
    if confidence_level is None:
        confidence_level = _config.reporting.bootstrap_confidence_level
    report_file = Path(report_path)
    
    if not report_file.exists():
        raise FileNotFoundError(
            f"Report file not found at: {report_file}. "
            f"Cannot update eval entries."
        )
    
    # Use pathlib.Path for output handling
    if output_path is None:
        output_file = report_file.with_suffix(".tmp")
        overwrite = True
    else:
        output_file = Path(output_path)
        overwrite = False
    
    try:
        with open(report_file, "r", encoding="utf-8") as infile, \
             open(output_file, "w", encoding="utf-8") as outfile:
            
            for line_num, line in enumerate(infile, 1):
                try:
                    entry = json.loads(line.strip())
                except json.JSONDecodeError as e:
                    raise json.JSONDecodeError(
                        f"Malformed JSON at line {line_num} in {report_file}: {e.msg}",
                        e.doc,
                        e.pos
                    ) from e
                
                if entry.get("entry_type") == "digest":
                    logging.debug("Stripping stale digest entry (will be recalculated)")
                    continue

                if entry.get("entry_type") == "start_run setup":
                    for param in _config.reporting_params:
                        entry[f"reporting.{param}"] = getattr(
                            _config.reporting, param
                        )

                if entry.get("entry_type") == "eval":
                    probe = entry.get("probe")
                    detector = entry.get("detector")
                    
                    if probe is None or detector is None:
                        outfile.write(json.dumps(entry, ensure_ascii=False) + "\n")
                        continue
                    
                    key = (probe, detector)
                    
                    if key in ci_results:
                        ci_lower, ci_upper = ci_results[key]
                        entry["confidence_method"] = (
                            confidence_methods.get(key, confidence_method)
                            if confidence_methods is not None
                            else confidence_method
                        )
                        entry["confidence"] = str(confidence_level)
                        entry["confidence_lower"] = ci_lower / 100.0  # Store as 0-1 scale
                        entry["confidence_upper"] = ci_upper / 100.0
                        
                        logging.debug(
                            "Updated CI for %s / %s: [%.2f, %.2f]",
                            probe,
                            detector,
                            ci_lower,
                            ci_upper
                        )
                
                outfile.write(json.dumps(entry, ensure_ascii=False) + "\n")
        
        if overwrite:
            output_file.replace(report_file)
            logging.info("Updated report file: %s", report_file)
        else:
            logging.info("Wrote updated report to: %s", output_file)
    
    except OSError as e:
        if overwrite and output_file.exists():
            output_file.unlink()
        raise OSError(f"Error updating report file {report_file}: {e}")
