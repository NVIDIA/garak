# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Helpers for plugins related migrations."""

import copy
import re

from garak import _plugins


def rename(config: dict, path: list[str], old: str, new: str):
    modified_root = copy.deepcopy(config)
    modified_config_entry = modified_root
    for sub_key in path:
        modified_config_entry = modified_config_entry.get(sub_key, None)
        if modified_config_entry and sub_key == "plugins":
            # revise spec keys, probe_spec, detector_spec, buff_spec
            for p_type, p_klass in zip(_plugins.PLUGIN_TYPES, _plugins.PLUGIN_CLASSES):
                type_spec = modified_config_entry.get(f"{p_klass.lower()}_spec", None)
                if p_type in path and type_spec is not None:
                    # This is more complex than a straight substitution
                    entries = type_spec.split(",")
                    updated_entries = []
                    for entry in entries:
                        if entry == old:
                            # if whole string just replace
                            entry = entry.replace(old, new)
                        elif old in path or f".{old}" in entry:
                            # if the old value is in `path` only sub f".{old}" representing class
                            entry = re.sub(rf"\.{old}$", f".{new}", entry)
                        else:
                            # else only sub for f"{old}." representing module
                            entry = entry.replace(f"{old}.", f"{new}.")
                        updated_entries.append(entry)
                    modified_config_entry[f"{p_klass.lower()}_spec"] = ",".join(
                        updated_entries
                    )
        if modified_config_entry is None:
            return modified_root
    config_for_rename = modified_config_entry.pop(old, None)
    if config_for_rename is not None:
        modified_config_entry[new] = config_for_rename
    return modified_root
