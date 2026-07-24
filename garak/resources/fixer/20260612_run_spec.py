# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Migrate the deprecated selection keys onto the unified ``run.spec`` grammar."""

import copy

from garak.resources.fixer import Migration
from garak._spec import legacy_selection_spec


def _reject_unknown_selectors(spec_dict: dict) -> None:
    """Fail migration if the converted ``run.spec`` names plugins that do not exist.

    A deprecated value with an invalid prefix (e.g. ``buff_spec: s.encoding.CharCode``)
    migrates syntactically but resolves to no plugin at run time; surfacing it here
    keeps ``--fix`` from emitting a config that fails when used.
    """
    from garak._spec import parse_spec_file
    from garak import _selection

    resolution = _selection.resolve_spec(parse_spec_file(spec_dict), skip_unknown=True)
    if resolution.rejected:
        raise ValueError(
            "config cannot be migrated to run.spec: the deprecated selection names "
            f"unknown plugins {resolution.rejected}; correct the source values "
            "(use an unprefixed '<module>[.<Class>]', e.g. 'encoding.CharCode') "
            "before migrating"
        )


class MapLegacySelectionToSpec(Migration):
    def apply(config_dict: dict) -> dict:
        """Convert ``plugins.probe_spec``/``buff_spec`` and ``run.probe_tags`` into ``run.spec``."""
        cfg = copy.deepcopy(config_dict)
        plugins = cfg.get("plugins", {})
        run = cfg.get("run", {})

        # an explicitly-set run.spec wins; the deprecated keys are then merely
        # dropped, mirroring garak._config._map_legacy_selection (ignored values
        # are not validated). Only convert - and validate - when run.spec is unset.
        if not run.get("spec"):
            try:
                spec = legacy_selection_spec(
                    plugins.get("probe_spec"),
                    plugins.get("buff_spec"),
                    run.get("probe_tags"),
                )
            except ValueError as exc:
                raise ValueError(f"config cannot be migrated to run.spec: {exc}") from exc
            if spec is None:  # nothing meaningful to migrate
                return cfg
            # drop empty include/exclude lists to keep the rewrite minimal
            run["spec"] = {key: value for key, value in spec.items() if value}
            _reject_unknown_selectors(run["spec"])

        plugins.pop("probe_spec", None)
        plugins.pop("buff_spec", None)
        run.pop("probe_tags", None)

        cfg["run"] = run
        # drop the plugins container if migration emptied it
        if plugins:
            cfg["plugins"] = plugins
        else:
            cfg.pop("plugins", None)
        return cfg
