# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import logging
from pathlib import Path
from typing import Optional, Dict, List, Tuple

from garak import _config
from garak.analyze.bootstrap_ci import calculate_bootstrap_ci
from garak.analyze.detector_metrics import get_detector_metrics


def _get_report_digest(report_path: str) -> Optional[dict]:
    """Extract digest entry from end of report JSONL"""
    with open(report_path, "r", encoding="utf-8") as reportfile:
        for entry in [json.loads(line.strip()) for line in reportfile if line.strip()]:
            if entry.get("entry_type") == "digest":
                return entry
    return None


def _reconstruct_binary_from_aggregates(passed: int, failed: int) -> List[int]:
    # Reconstruct binary pass/fail data from aggregates; order irrelevant for bootstrap resampling
    return [1] * passed + [0] * failed


def calculate_ci_from_report(
    report_path: str,
    probe_detector_pairs: Optional[List[Tuple[str, str]]] = None,
    num_iterations: Optional[int] = None,
    confidence_level: Optional[float] = None
) -> Dict[Tuple[str, str], Tuple[float, float]]:
    """Calculate bootstrap CIs for probe/detector pairs using report digest aggregates"""
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
        return {}
    
    # Load detector metrics for Se/Sp correction
    detector_metrics = get_detector_metrics()
    min_sample_size = _config.reporting.bootstrap_min_sample_size
    
    ci_results = {}
    
    # Iterate through digest structure: probe_group -> probe_class -> detector
    for probe_group in eval_data:
        for probe_key in eval_data[probe_group]:
            if probe_key == "_summary":
                continue
            
            # Parse probe module and class from key (format: "module.class")
            if "." not in probe_key:
                continue
            
            probe_name = f"probes.{probe_key}"
            
            for detector_key in eval_data[probe_group][probe_key]:
                if detector_key == "_summary":
                    continue
                
                detector_name = f"detector.{detector_key}"
                
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
                        detector_name
                    )
                    continue
                
                # Check minimum sample size
                if total < min_sample_size:
                    logging.warning(
                        "Insufficient samples for CI calculation: probe=%s, detector=%s, n=%d (minimum: %d)",
                        probe_name,
                        detector_name,
                        total,
                        min_sample_size
                    )
                    continue
                
                # Reconstruct binary data from aggregates
                # Order irrelevant: bootstrap resamples randomly with replacement
                failed = total - passed
                binary_results = _reconstruct_binary_from_aggregates(passed, failed)
                
                # Get detector Se/Sp for correction
                se, sp = detector_metrics.get_detector_se_sp(detector_key)
                
                # Calculate bootstrap CI
                ci_result = calculate_bootstrap_ci(
                    results=binary_results,
                    sensitivity=se,
                    specificity=sp,
                    num_iterations=num_iterations,
                    confidence_level=confidence_level
                )
                
                if ci_result is not None:
                    ci_results[(probe_name, detector_name)] = ci_result
                    logging.debug(
                        "Calculated CI for %s / %s: [%.2f, %.2f] (n=%d)",
                        probe_name,
                        detector_name,
                        ci_result[0],
                        ci_result[1],
                        total
                    )
    
    return ci_results


def update_eval_entries_with_ci(
    report_path: str,
    ci_results: Dict[Tuple[str, str], Tuple[float, float]],
    output_path: Optional[str] = None,
    confidence_method: Optional[str] = None,
    confidence_level: Optional[float] = None
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
                
                if entry.get("entry_type") == "eval":
                    probe = entry.get("probe")
                    detector = entry.get("detector")
                    
                    if probe is None or detector is None:
                        outfile.write(json.dumps(entry, ensure_ascii=False) + "\n")
                        continue
                    
                    key = (probe, detector)
                    
                    if key in ci_results:
                        ci_lower, ci_upper = ci_results[key]
                        entry["confidence_method"] = confidence_method
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
