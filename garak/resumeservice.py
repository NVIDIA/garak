# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Resume service for continuing interrupted garak scans.

This service handles loading and managing resume state from checkpoint files,
allowing scans to be resumed from where they left off.
"""

import hashlib
import json
import logging
import os
import uuid
from collections import defaultdict
from typing import Dict, Optional, Set, Tuple

from garak import _config
from garak.exception import GarakException


# Module-level state (replaces _config.transient storage)
_resume_state: Optional[Dict] = None


class ResumeValidationError(GarakException):
    """Raised when checkpoint validation fails."""

    pass


def enabled() -> bool:
    """Check if resume mode is active.

    Returns:
        True if a resume file has been specified, False otherwise.
    """
    return (
        hasattr(_config.transient, "resume_file")
        and _config.transient.resume_file is not None
    )


def start_msg() -> Tuple[str, str]:
    """Return startup message for resume service.

    Returns:
        Tuple of (emoji, message) for display during startup.
    """
    if enabled():
        return "🔄", f"resuming scan from: {_config.transient.resume_file}"
    return "", ""


def load() -> None:
    """Load and validate checkpoint file.

    This function parses the JSONL report file and extracts:
    - Completed attempts (status=2) that should be skipped entirely
    - Pending detection attempts (status=1) that need detection only

    Raises:
        FileNotFoundError: If the resume file doesn't exist.
        ResumeValidationError: If checkpoint validation fails.
    """
    global _resume_state

    if _resume_state is not None:
        # Already loaded
        return

    if not enabled():
        return

    resume_file = _config.transient.resume_file
    completed_seqs, pending, completed_data, metadata = _parse_checkpoint(resume_file)

    # Validate checkpoint
    _validate_checkpoint(metadata)

    # Store state
    _resume_state = {
        "completed": completed_seqs,
        "pending": pending,
        "completed_data": completed_data,
        "metadata": metadata,
        "resume_file": resume_file,
    }

    total_completed = sum(len(seqs) for seqs in completed_seqs.values())
    total_pending = sum(len(seqs) for seqs in pending.values())

    logging.info(
        f"Resume service loaded: {total_completed} completed, "
        f"{total_pending} pending detection across "
        f"{len(completed_seqs) + len(pending)} probes"
    )
    print(f"📊 Found {total_completed} completed, {total_pending} pending detection")


def _parse_checkpoint(
    resume_file: str,
) -> Tuple[Dict[str, Set[int]], Dict[str, Dict[int, dict]], Dict[str, Dict[int, dict]], Dict]:
    """Parse a JSONL report file and extract attempt data.

    Args:
        resume_file: Path to the JSONL report file.

    Returns:
        Tuple of (completed_seqs, pending_detection_attempts, completed_data, metadata) where:
        - completed_seqs: Dict mapping probe_classname to set of completed seq numbers
        - pending_detection_attempts: Dict mapping probe_classname to dict of {seq: attempt_data}
        - completed_data: Dict mapping probe_classname to dict of {seq: attempt_data} for completed
        - metadata: Dict containing run metadata (version, seed, probe_spec, etc.)
    """
    completed_seqs = defaultdict(set)
    completed_data = defaultdict(dict)
    pending_detection = defaultdict(dict)
    metadata = {
        "garak_version": None,
        "seed": None,
        "probe_spec": None,
    }

    try:
        with open(resume_file, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)

                    # Extract metadata from init entry
                    if entry.get("entry_type") == "init":
                        metadata["garak_version"] = entry.get("garak_version")

                    # Extract probe spec and seed from setup entry
                    if entry.get("entry_type") == "start_run setup":
                        metadata["probe_spec"] = entry.get("plugins.probe_spec")
                        metadata["seed"] = entry.get("run.seed")

                    # Process attempt entries
                    if entry.get("entry_type") == "attempt":
                        probe = entry.get("probe_classname")
                        seq = entry.get("seq")
                        status = entry.get("status")

                        if probe is not None and seq is not None:
                            if status == 2:
                                # status=2 (ATTEMPT_COMPLETE) - fully done
                                completed_seqs[probe].add(seq)
                                # Also store full data for prompt-based matching
                                completed_data[probe][seq] = entry
                            elif status == 1:
                                # status=1 (ATTEMPT_STARTED) - has response, needs detection
                                pending_detection[probe][seq] = entry

                except json.JSONDecodeError as e:
                    logging.warning(
                        f"Skipping malformed JSON at line {line_num} in resume file: {e}"
                    )
                    continue

    except FileNotFoundError:
        raise FileNotFoundError(f"Resume file not found: {resume_file}")
    except Exception as e:
        logging.error(f"Error reading resume file: {e}")
        raise

    return dict(completed_seqs), dict(pending_detection), dict(completed_data), metadata


def _validate_checkpoint(metadata: Dict) -> None:
    """Validate checkpoint metadata against current run.

    Args:
        metadata: Checkpoint metadata dict.

    Raises:
        ResumeValidationError: If validation fails critically.
    """
    # Check version compatibility
    checkpoint_version = metadata.get("garak_version")
    if checkpoint_version and checkpoint_version != _config.version:
        raise ResumeValidationError(
            f"Version mismatch: checkpoint version ({checkpoint_version}) differs from "
            f"current version ({_config.version}). Results would be inconsistent."
        )

    # Note: Seed validation removed - prompt-based matching handles reordering
    # The hash_prompt() function matches by content, not by seq position


# Public API functions


def get_completed_attempts() -> Dict[str, Set[int]]:
    """Get all completed attempts from checkpoint.

    Returns:
        Dict mapping probe_classname to set of completed seq numbers.
    """
    load()
    if _resume_state is None:
        return {}
    return _resume_state.get("completed", {})


def get_pending_detection_attempts() -> Dict[str, Dict[int, dict]]:
    """Get all pending detection attempts from checkpoint.

    Returns:
        Dict mapping probe_classname to dict of {seq: attempt_data}.
    """
    load()
    if _resume_state is None:
        return {}
    return _resume_state.get("pending", {})


def get_completed_seqs(probe_classname: str) -> Set[int]:
    """Get completed sequence numbers for a specific probe.

    Handles various probe name formats for backward compatibility:
    - Full format: "garak.probes.dan.Dan_11_0"
    - JSONL format: "probes.dan.Dan_11_0"
    - Short format: "dan.Dan_11_0"

    Args:
        probe_classname: The probe class name (any format).

    Returns:
        Set of completed seq numbers for this probe.
    """
    load()
    if _resume_state is None:
        return set()

    completed = _resume_state.get("completed", {})

    # Try exact match first
    if probe_classname in completed:
        return completed[probe_classname]

    # Normalize to different formats and try each
    # From "garak.probes.dan.Dan_11_0" -> "probes.dan.Dan_11_0"
    if probe_classname.startswith("garak."):
        without_garak = probe_classname[6:]  # Remove "garak." prefix
        if without_garak in completed:
            return completed[without_garak]

    # From "garak.probes.dan.Dan_11_0" -> "dan.Dan_11_0"
    if probe_classname.startswith("garak.probes."):
        short_name = probe_classname[13:]  # Remove "garak.probes." prefix
        if short_name in completed:
            return completed[short_name]

    # From "probes.dan.Dan_11_0" -> "dan.Dan_11_0"
    if probe_classname.startswith("probes."):
        short_name = probe_classname[7:]  # Remove "probes." prefix
        if short_name in completed:
            return completed[short_name]

    # Try adding "probes." prefix if short name was provided
    if not probe_classname.startswith("probes.") and not probe_classname.startswith("garak."):
        with_probes = f"probes.{probe_classname}"
        if with_probes in completed:
            return completed[with_probes]

    return set()


def get_pending_attempts(probe_classname: str) -> Dict[int, dict]:
    """Get pending detection attempts for a specific probe.

    Handles various probe name formats for backward compatibility:
    - Full format: "garak.probes.dan.Dan_11_0"
    - JSONL format: "probes.dan.Dan_11_0"
    - Short format: "dan.Dan_11_0"

    Args:
        probe_classname: The probe class name (any format).

    Returns:
        Dict of {seq: attempt_data} for pending detection attempts.
    """
    load()
    if _resume_state is None:
        return {}

    pending = _resume_state.get("pending", {})

    # Try exact match first
    if probe_classname in pending:
        return pending[probe_classname]

    # Normalize to different formats and try each
    # From "garak.probes.dan.Dan_11_0" -> "probes.dan.Dan_11_0"
    if probe_classname.startswith("garak."):
        without_garak = probe_classname[6:]  # Remove "garak." prefix
        if without_garak in pending:
            return pending[without_garak]

    # From "garak.probes.dan.Dan_11_0" -> "dan.Dan_11_0"
    if probe_classname.startswith("garak.probes."):
        short_name = probe_classname[13:]  # Remove "garak.probes." prefix
        if short_name in pending:
            return pending[short_name]

    # From "probes.dan.Dan_11_0" -> "dan.Dan_11_0"
    if probe_classname.startswith("probes."):
        short_name = probe_classname[7:]  # Remove "probes." prefix
        if short_name in pending:
            return pending[short_name]

    # Try adding "probes." prefix if short name was provided
    if not probe_classname.startswith("probes.") and not probe_classname.startswith("garak."):
        with_probes = f"probes.{probe_classname}"
        if with_probes in pending:
            return pending[with_probes]

    return {}


def is_attempt_completed(probe_classname: str, seq: int) -> bool:
    """Check if a specific attempt is already completed.

    Args:
        probe_classname: The probe class name.
        seq: The sequence number of the attempt.

    Returns:
        True if the attempt is completed, False otherwise.
    """
    return seq in get_completed_seqs(probe_classname)


def get_pending_attempt_data(probe_classname: str, seq: int) -> Optional[dict]:
    """Get data for a specific pending detection attempt.

    Args:
        probe_classname: The probe class name.
        seq: The sequence number of the attempt.

    Returns:
        Attempt data dict if pending, None otherwise.
    """
    pending = get_pending_attempts(probe_classname)
    return pending.get(seq)


def get_metadata() -> Dict:
    """Get checkpoint metadata.

    Returns:
        Dict containing checkpoint metadata (version, seed, probe_spec).
    """
    load()
    if _resume_state is None:
        return {}
    return _resume_state.get("metadata", {})


def reset() -> None:
    """Reset resume state (primarily for testing)."""
    global _resume_state
    _resume_state = None


def setup_run() -> bool:
    """Set up run for resume mode.

    This function handles all resume mode run setup responsibilities:
    - Sets the report filename to the resume file
    - Extracts run_id from the resume filename
    - Opens the report file in append mode
    - Writes a resume marker entry

    Returns:
        True if resume mode setup was performed, False if not in resume mode.
    """
    if not enabled():
        return False

    # Load checkpoint data
    load()

    logging.info(f"Resuming scan from: {_config.transient.resume_file}")

    # Use the same report file (append mode)
    _config.transient.report_filename = _config.transient.resume_file

    # Extract run_id from resume filename (format: garak.{run_id}.report.jsonl)
    resume_basename = os.path.basename(_config.transient.resume_file)
    if resume_basename.startswith("garak.") and resume_basename.endswith(
        ".report.jsonl"
    ):
        _config.transient.run_id = resume_basename[6:-13]  # Extract UUID from filename
    else:
        _config.transient.run_id = str(uuid.uuid4())

    # Open file in append mode
    _config.transient.reportfile = open(
        _config.transient.report_filename, "a", buffering=1, encoding="utf-8"
    )

    # Write resume marker to report
    completed_attempts = get_completed_attempts()
    pending_detection = get_pending_detection_attempts()
    total_completed = sum(len(seqs) for seqs in completed_attempts.values())
    total_pending = sum(len(seqs) for seqs in pending_detection.values())

    _config.transient.reportfile.write(
        json.dumps(
            {
                "entry_type": "resume",
                "resume_time": _config.transient.starttime_iso,
                "completed_attempts_count": total_completed,
                "pending_detection_count": total_pending,
                "probes_with_progress": list(
                    set(completed_attempts.keys()) | set(pending_detection.keys())
                ),
            },
            ensure_ascii=False,
        )
        + "\n"
    )

    return True


# Prompt-based matching functions


def _extract_prompt_text(prompt_dict: dict) -> str:
    """Extract text content from prompt structure.

    Args:
        prompt_dict: The prompt dictionary (Conversation format with turns).

    Returns:
        Concatenated text content from all turns.
    """
    turns = prompt_dict.get("turns", [])
    texts = []
    for turn in turns:
        content = turn.get("content", {})
        if isinstance(content, dict):
            texts.append(content.get("text", ""))
        elif isinstance(content, str):
            texts.append(content)
    return "|||".join(texts)


def hash_prompt(prompt_dict: dict) -> str:
    """Create consistent hash of prompt content.

    Args:
        prompt_dict: The prompt dictionary (Conversation format with turns).

    Returns:
        A 16-character hex hash of the prompt text.
    """
    prompt_text = _extract_prompt_text(prompt_dict)
    return hashlib.sha256(prompt_text.encode()).hexdigest()[:16]


def get_completed_by_prompt_hash(probe_classname: str) -> Dict[str, dict]:
    """Get completed attempts indexed by prompt hash.

    This allows matching attempts by prompt content instead of seq number,
    making resume robust to prompt reordering or filtering.

    Handles various probe name formats for backward compatibility.

    Args:
        probe_classname: The probe class name (any format).

    Returns:
        Dict mapping prompt_hash -> attempt_data for completed attempts.
    """
    load()
    if _resume_state is None:
        return {}

    completed_data = _resume_state.get("completed_data", {})

    # Find probe data with name normalization
    probe_data = _get_probe_data_normalized(completed_data, probe_classname)
    if not probe_data:
        return {}

    # Build hash index
    result = {}
    for attempt_data in probe_data.values():
        prompt = attempt_data.get("prompt", {})
        prompt_hash = hash_prompt(prompt)
        result[prompt_hash] = attempt_data

    return result


def _get_probe_data_normalized(data_dict: Dict, probe_classname: str) -> Optional[Dict]:
    """Get probe data with name normalization.

    Args:
        data_dict: The dictionary to search (completed_data or pending).
        probe_classname: The probe class name (any format).

    Returns:
        The probe's data dict or None if not found.
    """
    # Try exact match first
    if probe_classname in data_dict:
        return data_dict[probe_classname]

    # Normalize to different formats and try each
    # From "garak.probes.dan.Dan_11_0" -> "probes.dan.Dan_11_0"
    if probe_classname.startswith("garak."):
        without_garak = probe_classname[6:]
        if without_garak in data_dict:
            return data_dict[without_garak]

    # From "garak.probes.dan.Dan_11_0" -> "dan.Dan_11_0"
    if probe_classname.startswith("garak.probes."):
        short_name = probe_classname[13:]
        if short_name in data_dict:
            return data_dict[short_name]

    # From "probes.dan.Dan_11_0" -> "dan.Dan_11_0"
    if probe_classname.startswith("probes."):
        short_name = probe_classname[7:]
        if short_name in data_dict:
            return data_dict[short_name]

    # Try adding "probes." prefix if short name was provided
    if not probe_classname.startswith("probes.") and not probe_classname.startswith("garak."):
        with_probes = f"probes.{probe_classname}"
        if with_probes in data_dict:
            return data_dict[with_probes]

    return None
