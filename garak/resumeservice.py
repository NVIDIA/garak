# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Resume service for continuing interrupted garak scans at probe or attempt level.

This service manages run state persistence and provides configurable resumption
at either probe-level or attempt-level granularity. It maintains run state in
the XDG-compliant data directory (typically ~/.local/share/garak/runs/) and 
provides run management capabilities.

Architecture:
- Service pattern (follows langservice.py)
- Configurable granularity: probe-level or attempt-level
- Persistent state storage (separate from reports, in XDG data dir)
- Run management features (list, delete, resume)

Granularity Options:
- probe: Skip entire completed probes (faster, less granular)
- attempt: Skip individual completed attempts/prompts (slower, more granular)
"""

import json
import logging
import os
import tempfile
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from garak import _config
from garak.exception import GarakException, ResumeValidationError

logger = logging.getLogger(__name__)

# Module-level state
_resume_state: Optional[Dict] = None
_run_manager: Optional["RunManager"] = None


class RunManager:
    """Manages run state for resumable scans.

    Handles run state persistence, progress tracking, and run lifecycle
    management for resumable vulnerability scans.
    """

    def __init__(self):
        # Use XDG-compliant data directory for run state storage
        # State is stored separately from reports in the data directory
        self.run_dir = _config.transient.data_dir / "runs"
        self.run_dir.mkdir(parents=True, exist_ok=True)

    def generate_run_id(self, existing_uuid: str = None) -> str:
        """Generate unique run ID with timestamp.

        Args:
            existing_uuid: Optional UUID to use instead of generating a new one.
                          Useful for maintaining consistency with transient.run_id.

        Returns:
            A unique run ID string in format: garak-run-<uuid>-<timestamp>
        """
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        run_uuid = existing_uuid if existing_uuid else str(uuid.uuid4())
        return f"garak-run-{run_uuid}-{timestamp}"

    def save_state(self, run_id: str, state: Dict) -> None:
        """Save run state to disk atomically.

        Args:
            run_id: The run ID to save state for
            state: State dictionary to save

        Raises:
            Exception: If state saving fails
        """
        run_path = self.run_dir / run_id
        run_path.mkdir(exist_ok=True)
        state_file = run_path / "state.json"
        logger.debug(f"Attempting to save state to {state_file}")

        # Add garak version to state for compatibility checking
        state["garak_version"] = _config.version

        # Convert sets to lists for JSON serialization (including nested sets)
        def convert_sets_to_lists(obj):
            """Recursively convert sets to lists for JSON serialization"""
            if isinstance(obj, set):
                return list(obj)
            elif isinstance(obj, dict):
                return {k: convert_sets_to_lists(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_sets_to_lists(item) for item in obj]
            return obj

        serializable_state = convert_sets_to_lists(state)

        try:
            # Atomic write: write to temp file, then rename
            with tempfile.NamedTemporaryFile(
                "w",
                delete=False,
                dir=run_path,
                suffix=".tmp",
                encoding="utf-8",
            ) as temp_file:
                json.dump(serializable_state, temp_file, ensure_ascii=False, indent=2)
                temp_file.flush()
                temp_file_path = temp_file.name
            os.replace(temp_file_path, state_file)
            logger.info(f"State saved successfully to {state_file}")
        except Exception as e:
            logger.error(f"Failed to save state to {state_file}: {str(e)}")
            raise

    def load_state(self, run_id: str, validate_version: bool = True) -> Dict:
        """Load state for a run.

        Args:
            run_id: The run ID to load
            validate_version: If True, raise error on version mismatch. If False, only warn.

        Returns:
            State dictionary loaded from disk

        Raises:
            ValueError: If run not found or state file corrupted
        """
        run_path = self.run_dir / run_id
        state_file = run_path / "state.json"

        if not run_path.exists() or not state_file.exists():
            raise ValueError(f"No run found with ID: {run_id}")

        try:
            with open(state_file, "r", encoding="utf-8") as f:
                state = json.load(f)

            # Validate garak version compatibility
            if "garak_version" in state:
                if state["garak_version"] != _config.version:
                    msg = (
                        f"Run {run_id} was created with garak version {state['garak_version']}, "
                        f"but current version is {_config.version}."
                    )
                    logger.warning(msg)
                    if validate_version:
                        raise ValueError(
                            f"Version mismatch: run created with garak {state['garak_version']}, "
                            f"current version is {_config.version}"
                        )
            else:
                logger.debug(
                    f"Run {run_id} has no version information (older state format)."
                )

            # Convert lists back to sets for internal use
            if "completed_probes" in state and isinstance(
                state["completed_probes"], list
            ):
                state["completed_probes"] = set(state["completed_probes"])

            if "completed_attempts" in state and isinstance(
                state["completed_attempts"], list
            ):
                state["completed_attempts"] = set(state["completed_attempts"])

            if "probe_attempts" in state and isinstance(state["probe_attempts"], dict):
                # Convert nested lists to sets
                for probe_name, attempts in state["probe_attempts"].items():
                    if isinstance(attempts, list):
                        state["probe_attempts"][probe_name] = set(attempts)

            # Convert lists back to sets where appropriate
            if "completed_probes" in state and isinstance(
                state["completed_probes"], list
            ):
                state["completed_probes"] = set(state["completed_probes"])

            return state

        except json.JSONDecodeError as e:
            logger.error(f"Corrupted state file for run {run_id} at {state_file}: {e}")
            raise ValueError(f"Corrupted state file for run {run_id}: {e}")

    def list_runs(self) -> List[Dict]:
        """List all available runs with their status.

        Returns:
            List of dicts with run information (id, progress, start_time, total)
        """
        runs = []
        for d in self.run_dir.iterdir():
            if d.is_dir() and (d / "state.json").exists():
                try:
                    state = self.load_state(d.name, validate_version=False)
                    # Only include runs that are not finished and have valid probe data
                    finished = state.get("finished", False)
                    probenames = state.get("probenames", [])

                    # Skip runs without probe information (invalid/corrupted state)
                    if not probenames or finished:
                        continue

                    start_time = state.get("start_time", "")
                    # Handle None or empty start_time values
                    if not start_time:
                        start_time = "1970-01-01T00:00:00"

                    total = len(probenames)
                    completed = len(state.get("completed_probes", []))

                    runs.append(
                        {
                            "run_id": d.name,
                            "progress": completed,
                            "total": total,
                            "start_time": start_time,
                        }
                    )
                except (ValueError, KeyError) as e:
                    logger.warning(f"Skipping run {d.name} due to error: {e}")
                    continue

        # Sort by start_time, most recent first
        return sorted(
            runs,
            key=lambda x: x["start_time"] or "1970-01-01T00:00:00",
            reverse=True,
        )

    def delete_run(self, run_id: str) -> None:
        """Delete a run and its state.

        Args:
            run_id: The run ID to delete

        Raises:
            ValueError: If run not found
        """
        run_path = self.run_dir / run_id
        if run_path.exists():
            for file in run_path.iterdir():
                file.unlink()
            run_path.rmdir()
            logger.info(f"Deleted run {run_id}")
        else:
            raise ValueError(f"No run found with ID: {run_id}")


# Service API Functions


def enabled() -> bool:
    """Check if resume mode is active.

    Returns:
        True if resume mode is enabled, False otherwise.
    """
    return (
        hasattr(_config.transient, "resume_run_id")
        and _config.transient.resume_run_id is not None
    )


def get_current_run_id() -> str:
    """Get the current run ID, whether it's a new run or resumed run.

    Returns the active run ID or None if no run is active.
    """
    # First check resume_run_id (set for both new runs and resumed runs)
    if hasattr(_config.transient, "resume_run_id") and _config.transient.resume_run_id:
        return _config.transient.resume_run_id

    # Fallback to run_id (should not be needed, but just in case)
    if hasattr(_config.transient, "run_id") and _config.transient.run_id:
        logger.warning("Using run_id instead of resume_run_id for state save")
        return _config.transient.run_id

    logger.error("No run_id found in transient config!")
    return None


def start_msg() -> Tuple[str, str]:
    """Return startup message for resume service.

    Returns:
        Tuple of (symbol, message) for display.
    """
    if not enabled():
        return ("", "")

    run_id = _config.transient.resume_run_id
    if _resume_state:
        granularity = _resume_state.get("granularity", "probe")

        if granularity == "attempt":
            completed_count = len(_resume_state.get("completed_attempts", set()))
            # Estimate total attempts based on completed + expected from remaining probes
            total_probes = len(_resume_state.get("probenames", []))
            completed_probes = len(_resume_state.get("completed_probes", set()))
            # This is an approximation since we don't know attempt count upfront
            msg = f"Resuming run {run_id} (attempt-level): {completed_count} attempts completed, {completed_probes}/{total_probes} probes done"
        else:
            completed_count = len(_resume_state.get("completed_probes", set()))
            total_count = len(_resume_state.get("probenames", []))
            msg = f"Resuming run {run_id} (probe-level): {completed_count}/{total_count} probes completed"

        return ("🔄", msg)

    return ("", "")


def load() -> None:
    """Initialize and load resume service state.

    Called automatically by harness during _initialize_runtime_services().
    Loads state if resume mode is active.

    Raises:
        GarakException: If resume state cannot be loaded
    """
    global _resume_state, _run_manager

    if not enabled():
        return

    _run_manager = RunManager()
    run_id = _config.transient.resume_run_id

    try:
        state = _run_manager.load_state(run_id)
        _resume_state = state
        logger.info(f"Resume service loaded state for run {run_id}")
    except ValueError as e:
        logger.error(f"Failed to load resume state: {e}")
        raise GarakException(f"Cannot resume run {run_id}: {e}")


def get_state() -> Optional[Dict]:
    """Get the current resume state.

    Returns:
        Resume state dictionary or None if no state loaded.
    """
    global _resume_state, _run_manager

    # If state is already loaded, return it
    if _resume_state is not None:
        return _resume_state

    # If resume is enabled but state not loaded yet, load it
    if enabled():
        if _run_manager is None:
            _run_manager = RunManager()

        run_id = _config.transient.resume_run_id
        try:
            state = _run_manager.load_state(run_id)
            _resume_state = state
            logger.info(f"Resume service loaded state for run {run_id}")
            return _resume_state
        except ValueError as e:
            logger.error(f"Failed to load resume state: {e}")
            return None

    return None


# Public API for Harnesses


def is_probe_resumable(probe_instance) -> bool:
    """Check if a probe instance supports resume functionality.

    Checks the probe's supports_resume attribute. TreeSearchProbe and
    IterativeProbe set this to False due to complex internal state.

    Args:
        probe_instance: Instance of a probe class

    Returns:
        True if probe supports resume, False otherwise
    """
    return getattr(probe_instance, "supports_resume", True)


def should_skip_probe(probe_classname: str) -> bool:
    """Check if a probe should be skipped (already completed).

    Args:
        probe_classname: Full probe class name (e.g., "garak.probes.dan.Dan_11_0")

    Returns:
        True if probe is already completed, False otherwise.
    """
    if not enabled() or _resume_state is None:
        return False

    completed_probes = _resume_state.get("completed_probes", set())

    # Handle different name formats
    # e.g., "garak.probes.dan.Dan_11_0" or "dan.Dan_11_0"
    probe_short = probe_classname.replace("garak.probes.", "")

    return probe_short in completed_probes or probe_classname in completed_probes


def mark_probe_complete(probe_classname: str) -> None:
    """Mark a probe as completed and save state.

    Args:
        probe_classname: Full probe class name.
    """
    if not enabled() or _resume_state is None:
        return

    probe_short = probe_classname.replace("garak.probes.", "")
    completed_probes = _resume_state.get("completed_probes", set())
    if not isinstance(completed_probes, set):
        completed_probes = set(completed_probes)
        _resume_state["completed_probes"] = completed_probes

    completed_probes.add(probe_short)
    _resume_state["progress"] = len(completed_probes)

    # Save state after each probe
    run_id = get_current_run_id()
    if run_id and _run_manager and _config.run.resumable:
        _run_manager.save_state(run_id, _resume_state)
        logger.info(f"Marked probe {probe_short} as complete")


def get_run_id() -> Optional[str]:
    """Get current or resumed run ID.

    Returns:
        Run ID string or None.
    """
    if enabled() and _resume_state:
        return _resume_state.get("run_id")
    return None


def extract_uuid_from_run_id(run_id: str) -> str:
    """Extract the UUID portion from a full run_id.

    Format: garak-run-<uuid>-<timestamp>
    Returns: <uuid>

    Args:
        run_id: Full run_id string

    Returns:
        UUID string (36 chars), or the input if it's already just a UUID
    """
    if run_id.startswith("garak-run-"):
        # Format: garak-run-<uuid>-<timestamp>
        # Split by dash and get the UUID (between first and second dashes after "garak-run")
        parts = run_id.split("-")
        if len(parts) >= 5:
            # garak-run-<uuid-part-1>-<uuid-part-2>-<uuid-part-3>-<uuid-part-4>-<uuid-part-5>-<timestamp>
            # UUID is parts[2:7] joined by dashes
            uuid_part = "-".join(parts[2:7])
            if len(uuid_part) == 36:  # Standard UUID length
                return uuid_part
    # If already a UUID or unparseable, return as-is
    return run_id


def initialize_new_run(
    probenames: List[str], generator=None, existing_run_uuid: str = None
) -> str:
    """Initialize a new resumable run.

    Args:
        probenames: List of probe names to be executed.
        generator: The generator instance (optional, for saving resume info)
        existing_run_uuid: Optional existing UUID from _config.transient.run_id to maintain consistency

    Returns:
        Generated run ID.
    """
    # Delegate to the version with attempt support
    return initialize_new_run_with_attempts(
        probenames, generator, existing_run_uuid=existing_run_uuid
    )


def mark_run_complete() -> None:
    """Mark the current run as finished."""
    if _resume_state and _run_manager:
        _resume_state["finished"] = True
        run_id = _resume_state.get("run_id")
        if run_id and _config.run.resumable:
            _run_manager.save_state(run_id, _resume_state)
            logger.info(f"Marked run {run_id} as complete")


# Run Management Functions


def list_runs() -> List[Dict]:
    """List all available runs with their status.

    Returns:
        List of dicts with run information.
    """
    if _run_manager is None:
        manager = RunManager()
    else:
        manager = _run_manager

    return manager.list_runs()


def delete_run(run_id: str) -> None:
    """Delete a run and its state.

    Args:
        run_id: The run ID to delete.
    """
    if _run_manager is None:
        manager = RunManager()
    else:
        manager = _run_manager

    manager.delete_run(run_id)


# Attempt-Level Resume Functions


def get_granularity() -> str:
    """Get the configured resume granularity.

    Configuration hierarchy (highest to lowest priority):
    0. Resumed state (when resuming an existing run - LOCKED to original)
    1. CLI argument (--resume_granularity) - for NEW runs or explicit override
    2. Environment variable (GARAK_RESUME_GRANULARITY)
    3. Config file (run.resume_granularity)
    4. Default ('probe')

    Returns:
        'probe' or 'attempt' based on configuration.
    """
    # 0. When resuming, ALWAYS use the original run's granularity (unless CLI explicitly overrides)
    if _resume_state and "granularity" in _resume_state:
        state_granularity = _resume_state["granularity"]

        # Allow CLI to override even on resume (for debugging/testing)
        if hasattr(_config.transient, "args") and _config.transient.args:
            cli_value = getattr(_config.transient.args, "resume_granularity", None)
            if cli_value and cli_value in ("probe", "attempt"):
                if cli_value != state_granularity:
                    logger.warning(
                        f"⚠️  Overriding resumed run's granularity from '{state_granularity}' to '{cli_value}' "
                        f"(this may cause issues!)"
                    )
                logger.debug(f"Using resume granularity from CLI override: {cli_value}")
                return cli_value

        # Use the original run's granularity
        logger.debug(
            f"Using resume granularity from resumed state: {state_granularity}"
        )
        return state_granularity

    # For NEW runs, check configuration hierarchy

    # 1. Check CLI argument (highest priority for new runs)
    if hasattr(_config.transient, "args") and _config.transient.args:
        cli_value = getattr(_config.transient.args, "resume_granularity", None)
        if cli_value and cli_value in ("probe", "attempt"):
            logger.debug(f"Using resume granularity from CLI: {cli_value}")
            return cli_value

    # 2. Check environment variable
    env_value = os.getenv("GARAK_RESUME_GRANULARITY")
    if env_value and env_value.lower() in ("probe", "attempt"):
        logger.debug(f"Using resume granularity from environment: {env_value.lower()}")
        return env_value.lower()

    # 3. Check config file
    granularity = getattr(_config.run, "resume_granularity", "probe")
    if granularity in ("probe", "attempt"):
        logger.debug(f"Using resume granularity from config: {granularity}")
        return granularity

    # 4. Default
    logger.warning(f"Invalid resume_granularity '{granularity}', using default 'probe'")
    return "probe"


def should_skip_attempt(attempt_uuid: str) -> bool:
    """Check if an attempt should be skipped (already completed).

    Only used when resume_granularity is 'attempt'.

    Args:
        attempt_uuid: UUID of the attempt to check

    Returns:
        True if attempt is already completed, False otherwise.
    """
    if not enabled() or _resume_state is None:
        return False

    # Only skip attempts if we're in attempt-level mode
    if get_granularity() != "attempt":
        return False

    completed_attempts = _resume_state.get("completed_attempts", set())
    return str(attempt_uuid) in completed_attempts


def mark_attempt_complete(attempt_uuid: str, probe_classname: str) -> None:
    """Mark an attempt as completed and save state.

    Only used when resume_granularity is 'attempt'.

    Args:
        attempt_uuid: UUID of the completed attempt
        probe_classname: Name of the probe that generated this attempt
    """
    if not enabled() or _resume_state is None:
        return

    # Only track attempts if we're in attempt-level mode
    if get_granularity() != "attempt":
        return

    # Initialize completed_attempts set if it doesn't exist
    if "completed_attempts" not in _resume_state:
        _resume_state["completed_attempts"] = set()

    completed_attempts = _resume_state["completed_attempts"]
    if not isinstance(completed_attempts, set):
        completed_attempts = set(completed_attempts)
        _resume_state["completed_attempts"] = completed_attempts

    completed_attempts.add(str(attempt_uuid))

    # Also track which probe this attempt belongs to
    if "probe_attempts" not in _resume_state:
        _resume_state["probe_attempts"] = {}

    probe_short = probe_classname.replace("garak.probes.", "")
    if probe_short not in _resume_state["probe_attempts"]:
        _resume_state["probe_attempts"][probe_short] = set()

    probe_attempts = _resume_state["probe_attempts"][probe_short]
    if not isinstance(probe_attempts, set):
        probe_attempts = set(probe_attempts)
        _resume_state["probe_attempts"][probe_short] = probe_attempts

    probe_attempts.add(str(attempt_uuid))

    # Save state after each attempt (this is more frequent but ensures granular resume)
    run_id = get_current_run_id()
    if run_id and _run_manager and _config.run.resumable:
        _run_manager.save_state(run_id, _resume_state)
        logger.debug(
            f"Marked attempt {attempt_uuid} as complete for probe {probe_short}"
        )


def get_completed_attempts_for_probe(probe_classname: str) -> Set[str]:
    """Get set of completed attempt UUIDs for a specific probe.

    Args:
        probe_classname: Name of the probe

    Returns:
        Set of completed attempt UUIDs for this probe
    """
    if not enabled() or _resume_state is None:
        return set()

    probe_short = probe_classname.replace("garak.probes.", "")
    probe_attempts = _resume_state.get("probe_attempts", {})
    return set(probe_attempts.get(probe_short, set()))


def should_skip_attempt_by_seq(probe_classname: str, seq: int) -> bool:
    """Check if an attempt should be skipped based on probe name and sequence number.

    Uses deterministic (probename, seq) identifier instead of random UUID.
    Only used when resume_granularity is 'attempt'.

    Args:
        probe_classname: Name of the probe
        seq: Sequence number of the attempt

    Returns:
        True if attempt is already completed, False otherwise.
    """
    if not enabled() or _resume_state is None:
        return False

    # Only skip attempts if we're in attempt-level mode
    if get_granularity() != "attempt":
        return False

    probe_short = probe_classname.replace("garak.probes.", "").replace("probes.", "")
    attempt_id = f"{probe_short}:{seq}"

    completed_attempts = _resume_state.get("completed_attempts", set())
    result = attempt_id in completed_attempts
    return result


def mark_attempt_complete_by_seq(probe_classname: str, seq: int) -> None:
    """Mark an attempt as completed based on probe name and sequence number.

    Uses deterministic (probename, seq) identifier instead of random UUID.
    Only used when resume_granularity is 'attempt'.

    Args:
        probe_classname: Name of the probe
        seq: Sequence number of the attempt
    """
    logger.debug(
        f"mark_attempt_complete_by_seq called: probe={probe_classname}, seq={seq}"
    )
    logger.debug(
        f"enabled()={enabled()}, _resume_state={'None' if _resume_state is None else 'exists'}"
    )

    if not enabled() or _resume_state is None:
        logger.debug(
            f"Early return: enabled={enabled()}, _resume_state={'None' if _resume_state is None else 'exists'}"
        )
        return

    # Only track attempts if we're in attempt-level mode
    granularity = get_granularity()
    logger.debug(f"Current granularity: {granularity}")
    if granularity != "attempt":
        logger.debug(
            f"Skipping attempt tracking: granularity is '{granularity}', not 'attempt'"
        )
        return

    probe_short = probe_classname.replace("garak.probes.", "").replace("probes.", "")
    attempt_id = f"{probe_short}:{seq}"

    # Initialize completed_attempts set if it doesn't exist
    if "completed_attempts" not in _resume_state:
        _resume_state["completed_attempts"] = set()

    completed_attempts = _resume_state["completed_attempts"]
    if not isinstance(completed_attempts, set):
        completed_attempts = set(completed_attempts)
        _resume_state["completed_attempts"] = completed_attempts

    completed_attempts.add(attempt_id)

    # Also track in probe_attempts for convenience
    if "probe_attempts" not in _resume_state:
        _resume_state["probe_attempts"] = {}

    if probe_short not in _resume_state["probe_attempts"]:
        _resume_state["probe_attempts"][probe_short] = set()

    probe_attempts = _resume_state["probe_attempts"][probe_short]
    if not isinstance(probe_attempts, set):
        probe_attempts = set(probe_attempts)
        _resume_state["probe_attempts"][probe_short] = probe_attempts

    probe_attempts.add(attempt_id)

    logger.debug(f"Added attempt {attempt_id} to completed_attempts")

    # Save state after each attempt
    run_id = get_current_run_id()
    logger.debug(
        f"About to save state: run_id={run_id}, _run_manager={'None' if _run_manager is None else 'exists'}, resumable={_config.run.resumable}"
    )
    if run_id and _run_manager and _config.run.resumable:
        logger.info(f"Saving state for attempt {attempt_id}")
        _run_manager.save_state(run_id, _resume_state)
        logger.info(f"Marked attempt {attempt_id} as complete")
    else:
        logger.warning(
            f"Skipping state save: run_id={run_id}, _run_manager={'None' if _run_manager is None else 'exists'}, resumable={_config.run.resumable}"
        )


def initialize_new_run_with_attempts(
    probenames: List[str], generator=None, existing_run_uuid: str = None
) -> str:
    """Initialize a new resumable run with attempt tracking support.

    Args:
        probenames: List of probe names to be executed.
        generator: The generator instance (optional, for saving resume info)
        existing_run_uuid: Optional existing UUID from _config.transient.run_id to maintain consistency

    Returns:
        Generated run ID.
    """
    global _resume_state, _run_manager

    if _run_manager is None:
        _run_manager = RunManager()

    run_id = _run_manager.generate_run_id(existing_uuid=existing_run_uuid)

    # Preserve original start_time if available (for resumed runs)
    original_start_time = (
        _config.transient.original_start_time
        if hasattr(_config.transient, "original_start_time")
        and _config.transient.original_start_time
        else datetime.now().isoformat()
    )

    _resume_state = {
        "run_id": run_id,
        "probenames": probenames,
        "completed_probes": set(),
        "completed_attempts": set(),  # Track completed attempts
        "probe_attempts": {},  # Map probe -> set of attempt UUIDs
        "probes": {},  # Map probe -> {prompt_index, total_prompts} for resume point calculation
        "current_probe": None,  # Currently executing probe
        "current_prompt_index": 0,  # Last completed prompt index for current probe
        "progress": 0,
        "granularity": get_granularity(),
        "start_time": original_start_time,  # Use original start_time from report if resuming
        "finished": False,
    }

    # Save generator and model info for resume
    if generator is not None:
        generator_class = (
            f"{generator.__class__.__module__}.{generator.__class__.__name__}"
        )
        _resume_state["generator"] = generator_class

        # Extract model_type and model_name
        if hasattr(generator, "name"):
            _resume_state["model_name"] = generator.name
        if hasattr(generator, "model_type"):
            _resume_state["model_type"] = generator.model_type
        elif "." in generator_class:
            # Extract from class path: garak.generators.openai.OpenAIGenerator -> openai
            parts = generator_class.split(".")
            if len(parts) >= 3 and parts[0] == "garak" and parts[1] == "generators":
                _resume_state["model_type"] = parts[2]

    # Save the full generator configuration from _config
    if hasattr(_config.plugins, "generators") and _config.plugins.generators:
        _resume_state["generator_config"] = _config.plugins.generators

    # Save run configuration parameters
    if hasattr(_config.run, "generations"):
        _resume_state["run_generations"] = _config.run.generations
    if hasattr(_config.run, "deprefix"):
        _resume_state["run_deprefix"] = _config.run.deprefix

    # Save report directory and prefix for resume
    if hasattr(_config.reporting, "report_dir"):
        _resume_state["report_dir"] = _config.reporting.report_dir
    if hasattr(_config.reporting, "report_prefix"):
        _resume_state["report_prefix"] = _config.reporting.report_prefix
    if hasattr(_config.reporting, "group_aggregation_function"):
        _resume_state["reporting_group_aggregation_function"] = (
            _config.reporting.group_aggregation_function
        )

    # Save probe_spec, target_type, target_name for digest metadata
    if hasattr(_config.plugins, "probe_spec"):
        _resume_state["probe_spec"] = _config.plugins.probe_spec
    if hasattr(_config.plugins, "target_type"):
        _resume_state["target_type"] = _config.plugins.target_type
    if hasattr(_config.plugins, "target_name"):
        _resume_state["target_name"] = _config.plugins.target_name

    if _config.run.resumable:
        _run_manager.save_state(run_id, _resume_state)

    # Set resume_run_id for tracking THIS run's resumable state
    # Only set if not already set (i.e., this is a fresh run, not a resumed run)
    if (
        not hasattr(_config.transient, "resume_run_id")
        or _config.transient.resume_run_id is None
    ):
        _config.transient.resume_run_id = run_id

    logger.info(
        f"Initialized new resumable run {run_id} with granularity={get_granularity()}"
    )
    return run_id


def save_probe_progress(
    probe_classname: str, prompt_index: int, total_prompts: int
) -> None:
    """Save progress for a probe at the prompt level.

    This tracks the last completed prompt index and total prompts for each probe,
    enabling precise resume from the next prompt.

    Args:
        probe_classname: Name of the probe
        prompt_index: Index of last completed prompt (0-based)
        total_prompts: Total number of prompts for this probe
    """
    if not enabled() or _resume_state is None:
        logger.debug(
            f"save_probe_progress skipped: enabled={enabled()}, _resume_state={'None' if _resume_state is None else 'exists'}"
        )
        return

    probe_short = probe_classname.replace("garak.probes.", "").replace("probes.", "")

    # Initialize probes dict if it doesn't exist
    if "probes" not in _resume_state:
        _resume_state["probes"] = {}

    # Update probe progress
    _resume_state["probes"][probe_short] = {
        "prompt_index": prompt_index,
        "total_prompts": total_prompts,
    }
    _resume_state["current_probe"] = probe_short
    _resume_state["current_prompt_index"] = prompt_index

    logger.info(
        f"[RESUME DEBUG] Updated _resume_state for {probe_short}: prompt_index={prompt_index}, total_prompts={total_prompts}"
    )
    logger.info(
        f"[RESUME DEBUG] Current probes in state: {list(_resume_state.get('probes', {}).keys())}"
    )
    logger.debug(
        f"Updated probe progress: {probe_short} at {prompt_index}/{total_prompts}"
    )

    # Save state after updating prompt progress
    run_id = get_current_run_id()
    logger.info(
        f"[RESUME DEBUG] About to save state: run_id={run_id}, resumable={_config.run.resumable}"
    )
    if run_id and _run_manager and _config.run.resumable:
        _run_manager.save_state(run_id, _resume_state)
        logger.info(
            f"[RESUME DEBUG] ✅ State saved to disk for {probe_short} at prompt {prompt_index}/{total_prompts}"
        )
        logger.debug(
            f"Saved progress: {probe_short} at prompt {prompt_index}/{total_prompts}"
        )
    else:
        logger.error(
            f"[RESUME DEBUG] ❌ Failed to save state: run_id={run_id}, _run_manager={'None' if _run_manager is None else 'exists'}, resumable={_config.run.resumable}"
        )
        logger.warning(
            f"Skipping progress save: run_id={run_id}, _run_manager={'None' if _run_manager is None else 'exists'}, resumable={_config.run.resumable}"
        )


def get_resume_point(probe_classname: str) -> int:
    """Get the next prompt index to execute for a probe.

    Calculates where to resume execution based on saved state.

    Args:
        probe_classname: Name of the probe

    Returns:
        Next prompt index to process (resume_point)
        - If probe not in state: return 0 (start from beginning)
        - If probe completed all prompts: return total_prompts (done)
        - Otherwise: return prompt_index + 1 (next prompt after last completed)

    Example:
        - prompt_index=3, total_prompts=10 → resume_point=4
        - prompt_index=9, total_prompts=10 → resume_point=10 (done)
        - probe not found → resume_point=0 (start fresh)
    """
    if not enabled() or _resume_state is None:
        return 0

    probe_short = probe_classname.replace("garak.probes.", "").replace("probes.", "")
    probes = _resume_state.get("probes", {})

    if probe_short in probes:
        probe_state = probes[probe_short]
        prompt_index = probe_state.get("prompt_index", -1)
        total_prompts = probe_state.get("total_prompts", 0)

        # Resume from next prompt after last completed
        resume_point = prompt_index + 1

        logger.info(
            f"[RESUME DEBUG] get_resume_point for {probe_short}: prompt_index={prompt_index}, total_prompts={total_prompts}, resume_point={resume_point}"
        )
        logger.debug(
            f"Resume point for {probe_short}: {resume_point}/{total_prompts} "
            f"(last completed: {prompt_index})"
        )

        return resume_point

    # No state found, start from beginning
    logger.debug(f"No saved state for {probe_short}, starting from prompt 0")
    return 0


def get_probe_state(probe_classname: str) -> Optional[Dict]:
    """Get the saved state for a specific probe.

    Args:
        probe_classname: Name of the probe

    Returns:
        Dictionary with 'prompt_index' and 'total_prompts', or None if not found
    """
    if not enabled() or _resume_state is None:
        return None

    probe_short = probe_classname.replace("garak.probes.", "").replace("probes.", "")
    probes = _resume_state.get("probes", {})

    return probes.get(probe_short, None)


def get_total_prompts(probe_classname: str) -> int:
    """Get the total number of prompts for a probe from saved state.

    Args:
        probe_classname: Name of the probe

    Returns:
        Total number of prompts, or 0 if not found
    """
    if not enabled() or _resume_state is None:
        return 0

    probe_short = probe_classname.replace("garak.probes.", "").replace("probes.", "")
    probes = _resume_state.get("probes", {})

    if probe_short in probes:
        return probes[probe_short].get("total_prompts", 0)

    return 0
