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


def migrate(original_config: dict) -> dict:
    import copy

    updated_config = copy.deepcopy(original_config)
    for migration in ordered_migrations:
        new_config = migration.apply(updated_config)
        if new_config != updated_config:
            updated_config = new_config
            msg = f"Applied migrations changes from {migration.__name__}"
            logging.info(msg)

    if original_config != updated_config:
        logging.info("Migration performed")

    return updated_config
