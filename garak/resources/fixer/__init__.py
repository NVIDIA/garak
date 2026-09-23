# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Configuration migration utilities

Utility for processing loaded configuration files to apply updates for compatibility
"""

import importlib
import inspect
import logging
import os
from pathlib import Path


class Migration:
    """Required interface for migrations"""

    def apply(config_dict: dict) -> dict:
        raise NotImplementedError


# list of migrations, should this be dynamically built from the package?
ordered_migrations = []
root_path = Path(__file__).parents[0]
for module_filename in sorted(os.listdir(root_path)):
    if not module_filename.endswith(".py"):
        continue
    if module_filename.startswith("__"):
        continue
    module_name = module_filename[:-3]  # strip ".py" known from check above
    mod = importlib.import_module(f"{__package__}.{module_name}")
    migrations = sorted(
        [  # Extract only classes that are a `Migration`
            klass
            for _, klass in inspect.getmembers(mod, inspect.isclass)
            if klass.__module__.startswith(mod.__name__)
            and Migration in klass.__bases__
        ],
        key=lambda x: x.__name__.__str__(),
    )
    ordered_migrations += migrations


def _run_spec(config: dict) -> dict | None:
    run_config = config.get("run")
    if not isinstance(run_config, dict):
        return None
    spec = run_config.get("spec")
    return spec if isinstance(spec, dict) else None


def _reject_unknown_selectors(spec_dict: dict) -> None:
    from garak import _selection
    from garak._spec import parse_spec_file

    resolution = _selection.resolve_spec(parse_spec_file(spec_dict), skip_unknown=True)
    if resolution.rejected:
        raise ValueError(
            "config cannot be migrated to run.spec: the deprecated selection names "
            f"unknown plugins {resolution.rejected}; correct the source values "
            "(use an unprefixed '<module>[.<Class>]', e.g. 'encoding.CharCode') "
            "before migrating"
        )


def migrate(original_config: dict) -> dict:
    import copy

    original_spec = _run_spec(original_config)
    updated_config = copy.deepcopy(original_config)
    for migration in ordered_migrations:
        new_config = migration.apply(updated_config)
        if new_config != updated_config:
            updated_config = new_config
            msg = f"Applied migrations changes from {migration.__name__}"
            logging.info(msg)

    updated_spec = _run_spec(updated_config)
    if updated_spec is not None and updated_spec != original_spec:
        _reject_unknown_selectors(updated_spec)

    if original_config != updated_config:
        logging.info("Migration performed")

    return updated_config
