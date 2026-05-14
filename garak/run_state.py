# SPDX-FileCopyrightText: Portions Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""garak.run_state: on-disk state for probe-level resumable scans.

State for a single run lives at::

    <xdg_data_home>/garak/runs/<run_id>/state.json

This module is pure file I/O. It does not know about probes, harnesses, or
the CLI. Callers are responsible for deciding when to create state, when to
load it, and when to mark a probe as complete.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Optional


def _state_path(run_id: str) -> Path:
    """Return the on-disk state.json path for ``run_id``."""
    from garak import _config

    return Path(_config.transient.data_dir) / "runs" / run_id / "state.json"


def create_run(
    run_id: str,
    probe_spec: str,
    generator_name: str,
    report_dir: str,
    report_prefix: str,
) -> dict:
    """Create and persist a fresh state.json for ``run_id``.

    Returns the new state dict. Overwrites any existing state for the same id.
    """
    state = {
        "run_id": run_id,
        "probe_spec": probe_spec or "",
        "generator_name": generator_name or "",
        "report_dir": report_dir or "",
        "report_prefix": report_prefix or "",
        "completed_probes": [],
    }
    save_state(state)
    return state


def load_state(
    run_id: str,
    expected_probe_spec: Optional[str] = None,
    expected_generator: Optional[str] = None,
) -> dict:
    """Load state.json for ``run_id``.

    Raises ``FileNotFoundError`` if no state exists. If
    ``expected_probe_spec`` or ``expected_generator`` are provided, raises
    ``ValueError`` when the stored values do not match.
    """
    path = _state_path(run_id)
    if not path.exists():
        raise FileNotFoundError(f"no saved run state for {run_id!r}")
    state = json.loads(path.read_text(encoding="utf-8"))

    if (
        expected_probe_spec is not None
        and (state.get("probe_spec") or "") != expected_probe_spec
    ):
        raise ValueError(
            "resume: probe_spec does not match original run "
            f"(stored={state.get('probe_spec')!r}, current={expected_probe_spec!r})"
        )
    if (
        expected_generator is not None
        and (state.get("generator_name") or "") != expected_generator
    ):
        raise ValueError(
            "resume: generator does not match original run "
            f"(stored={state.get('generator_name')!r}, current={expected_generator!r})"
        )
    return state


def save_state(state: dict) -> None:
    """Atomically write ``state`` to its on-disk location.

    Requires ``state['run_id']`` to be set.
    """
    run_id = state["run_id"]
    path = _state_path(run_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", delete=False, dir=str(path.parent)
    ) as tmp:
        json.dump(state, tmp, ensure_ascii=False, indent=2)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_name = tmp.name
    Path(tmp_name).replace(path)


def mark_probe_complete(run_id: str, probe_name: str) -> None:
    """Append ``probe_name`` to the run's completed_probes list and persist.

    Idempotent: a probe already in the list is left untouched.
    """
    state = load_state(run_id)
    if probe_name not in state["completed_probes"]:
        state["completed_probes"].append(probe_name)
        save_state(state)
