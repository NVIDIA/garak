# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import logging
from pathlib import Path
from typing import Optional, Dict, List, Tuple

from garak import _config
from garak.analyze.bootstrap_ci import calculate_bootstrap_ci, BOOTSTRAP_MIN_SAMPLE_SIZE
from garak.analyze.detector_metrics import get_detector_metrics
from garak.attempt import ATTEMPT_COMPLETE


def reconstruct_binary_results(
    attempts: List[dict],
    probe_name: str,
    detector_name: str,
    eval_threshold: float
) -> List[int]:
    """Extract binary pass/fail outcomes from attempt records for probe/detector pair"""
    binary_results = []
    
    for attempt in attempts:
        if attempt.get("probe_classname") != probe_name:
            continue
        
        if attempt.get("status") != ATTEMPT_COMPLETE:
            continue
        
        detector_results = attempt.get("detector_results", {})
        if detector_name not in detector_results:
            continue
        
        scores = detector_results[detector_name]
        for score in scores:
            if score is None:
                continue
            try:
                score_float = float(score)
            except (ValueError, TypeError) as e:
                logging.warning(
                    "Invalid score value '%s' for probe=%s, detector=%s: %s. Skipping.",
                    score, probe_name, detector_name, e
                )
                continue
            binary_results.append(0 if score_float < eval_threshold else 1)
    
    if not binary_results:
        raise ValueError(
            f"No results found for probe '{probe_name}' with detector '{detector_name}'. "
            f"Check that probe and detector names match report entries."
        )
    
    return binary_results


def calculate_ci_from_report(
    report_path: str,
    probe_detector_pairs: Optional[List[Tuple[str, str]]] = None,
    num_iterations: Optional[int] = None,
    confidence_level: Optional[float] = None
) -> Dict[Tuple[str, str], Tuple[float, float]]:
    """Calculate CIs for probe/detector pairs from report JSONL, params default to _config"""
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
    
    # Parse report
    setup_entry = None
    attempts = []
    eval_entries = []
    
    try:
        with open(report_file, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                try:
                    entry = json.loads(line.strip())
                except json.JSONDecodeError as e:
                    raise json.JSONDecodeError(
                        f"Malformed JSON at line {line_num} in {report_file}: {e.msg}",
                        e.doc,
                        e.pos
                    ) from e
                
                entry_type = entry.get("entry_type")
                if entry_type == "start_run setup":
                    setup_entry = entry
                elif entry_type == "attempt":
                    attempts.append(entry)
                elif entry_type == "eval":
                    eval_entries.append(entry)
    
    except OSError as e:
        raise OSError(f"Error reading report file {report_file}: {e}")
    
    if setup_entry is None:
        raise ValueError(
            f"Report {report_file} missing 'start_run setup' entry. "
            f"Cannot determine eval_threshold for binary conversion."
        )
    
    eval_threshold = setup_entry.get("run.eval_threshold")
    if eval_threshold is None:
        logging.warning(
            "No eval_threshold found in setup entry for %s, using default 0.5",
            report_file
        )
        eval_threshold = 0.5
    
    # Determine which probe/detector pairs to process
    if probe_detector_pairs is None:
        probe_detector_pairs = []
        for entry in eval_entries:
            probe = entry.get("probe")
            detector = entry.get("detector")
            if probe is not None and detector is not None:
                probe_detector_pairs.append((probe, detector))
    
    if not probe_detector_pairs:
        logging.warning("No probe/detector pairs found in report %s", report_file)
        return {}
    
    # Load detector metrics for Se/Sp correction
    detector_metrics = get_detector_metrics()
    
    ci_results = {}
    
    for probe_name, detector_name in probe_detector_pairs:
        try:
            # Reconstruct binary results
            binary_results = reconstruct_binary_results(
                attempts, probe_name, detector_name, eval_threshold
            )
            
            # Check minimum sample size (imported constant - single source of truth)
            if len(binary_results) < BOOTSTRAP_MIN_SAMPLE_SIZE:
                logging.warning(
                    "Insufficient samples for CI calculation: probe=%s, detector=%s, n=%d (minimum: %d)",
                    probe_name,
                    detector_name,
                    len(binary_results),
                    BOOTSTRAP_MIN_SAMPLE_SIZE
                )
                continue
            
            # Get detector Se/Sp
            se, sp = detector_metrics.get_detector_se_sp(detector_name)
            
            # Calculate CI
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
                    "Calculated CI for %s / %s: [%.2f, %.2f]",
                    probe_name,
                    detector_name,
                    ci_result[0],
                    ci_result[1]
                )
        
        except ValueError as e:
            logging.warning(
                "Could not calculate CI for %s / %s: %s",
                probe_name,
                detector_name,
                e
            )
            continue
    
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
