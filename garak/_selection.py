# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Resolution of a ``run.spec`` selection against the plugin registry.

The grammar (parsing/serialisation) lives in :mod:`garak._spec`; this module
turns a :class:`garak._spec.Spec` into concrete probe and buff names using the
active/tier/tag state from :mod:`garak._plugins`. :func:`resolve_spec` is the
single entry point used by the CLI and harnesses; the same plugin-path core
backs the ``parse_plugin_spec`` adapter used for detectors.
"""

from __future__ import annotations

import logging
from typing import List, Tuple

from garak import _plugins
from garak import _spec

# Tier assigned to probes that do not declare one (Tier.UNLISTED).
_DEFAULT_TIER = 9


def _resolve_plugin_paths(
    selectors: List[_spec.Selector], category: str
) -> Tuple[set, List[str], List[str]]:
    """Single plugin-path resolution core (category generic).

    Mirrors the legacy ``parse_plugin_spec`` name resolution:
    ``<category>.*`` -> active plugins; ``<category>.<module>`` -> active
    family; ``<category>.<module>.<Class>`` -> exact match (ignores ``active``).
    Returns ``(names, unknown, inactive)``: the resolved name set, selectors
    naming nothing recognised, and bare-module selectors that exist but whose
    plugins are all inactive (known-but-empty, distinct from unknown).
    """
    enumerated = _plugins.enumerate_plugins(category=category)
    names: set = set()
    rejected: List[str] = []
    inactive: List[str] = []
    prefix = f"{category}."
    for selector in selectors:
        if selector.kind == "none":
            # explicit empty selection contributes nothing (and is not unknown)
            continue
        token = selector.value
        body = token[len(prefix):] if token.startswith(prefix) else token
        if body == "*":
            names |= {p for p, active in enumerated if active is True}
        elif body.count(".") < 1:
            family = [
                (p, active)
                for p, active in enumerated
                if p.startswith(f"{category}.{body}.")
            ]
            active_names = {p for p, active in family if active is True}
            if active_names:
                names |= active_names
            elif family:  # module exists but every plugin is inactive
                inactive.append(token)
            else:
                rejected.append(token)
        else:
            found = {p for p, _ in enumerated if p == f"{category}.{body}"}
            if found:
                names |= found
            else:
                rejected.append(token)
    return names, rejected, inactive


def _has_any_tag(name: str, prefixes: List[str]) -> bool:
    tags = _plugins.plugin_info(name).get("tags") or []
    return any(tag.startswith(prefix) for tag in tags for prefix in prefixes)


def _tier_of(name: str) -> int:
    return int(_plugins.plugin_info(name).get("tier", _DEFAULT_TIER))


def _empty_reason(spec: _spec.Spec) -> str:
    """Best-effort explanation of why a spec resolved to no probes."""
    tier_ceilings = [int(s.value) for s in spec.include if s.kind == "tier"]
    explicit = [
        s.value
        for s in spec.include
        if s.kind == "plugin_path"
        and s.category == "probes"
        and s.value.count(".") >= 2
    ]
    if tier_ceilings and explicit:
        ceiling = max(tier_ceilings)
        name = explicit[0]
        return (
            f"probe '{name}' is tier {_tier_of(name)} but the spec restricts to "
            f"tiers 1..{ceiling}; widen the tier filter or drop the explicit probe"
        )
    if any(s.kind in ("tag", "tier") for s in spec.include):
        return "no active probe matches the given tier/tag filters; widen the filters"
    return "every included probe was removed by an exclusion; adjust includes/excludes"


def resolve_spec(spec: _spec.Spec, skip_unknown: bool = False) -> _spec.Resolution:
    """Resolve a :class:`garak._spec.Spec` to concrete probe and buff names.

    Selection happens against the live plugin registry (active state, tiers,
    tags). This is the single entry point used by the CLI and harnesses.
    """
    rejected: List[str] = []
    inactive_modules: List[str] = []

    # Layer 1: probe candidate set from plugin-path includes; default probes.*
    # unless an explicit ``none`` selector requests an empty probe selection.
    probe_includes = [
        s for s in spec.include if s.kind == "plugin_path" and s.category == "probes"
    ]
    probe_none = any(
        s.kind == "none" and s.category == "probes" for s in spec.include
    )
    if probe_includes:
        candidate, rej, inact = _resolve_plugin_paths(probe_includes, "probes")
        rejected += rej
        inactive_modules += inact
    elif probe_none:
        candidate = set()
    else:
        candidate = {
            p
            for p, active in _plugins.enumerate_plugins(category="probes")
            if active is True
        }

    # Layer 2: positive filters (tier log-level + tag), combined with AND
    tier_ceilings = [int(s.value) for s in spec.include if s.kind == "tier"]
    if tier_ceilings:
        ceiling = max(tier_ceilings)
        candidate = {p for p in candidate if _tier_of(p) <= ceiling}
    tag_prefixes = [s.value for s in spec.include if s.kind == "tag"]
    if tag_prefixes:
        candidate = {p for p in candidate if _has_any_tag(p, tag_prefixes)}

    # Buffs: union of buffs.* includes (no implicit default)
    buff_includes = [
        s for s in spec.include if s.kind == "plugin_path" and s.category == "buffs"
    ]
    if buff_includes:
        buffs, rej, inact = _resolve_plugin_paths(buff_includes, "buffs")
        rejected += rej
        inactive_modules += inact
    else:
        buffs = set()

    # Excludes applied last (exclude wins)
    for selector in spec.exclude:
        if selector.kind == "plugin_path" and selector.category == "probes":
            removed, rej, _ = _resolve_plugin_paths([selector], "probes")
            rejected += rej
            candidate -= removed
        elif selector.kind == "plugin_path" and selector.category == "buffs":
            removed, rej, _ = _resolve_plugin_paths([selector], "buffs")
            rejected += rej
            buffs -= removed
        elif selector.kind == "tier":
            number = int(selector.value)
            removed = {p for p in candidate if _tier_of(p) == number}
            if not removed:
                logging.debug(
                    "run.spec: no active probe of tier %s to remove", number
                )
            candidate -= removed
        elif selector.kind == "tag":
            candidate = {p for p in candidate if not _has_any_tag(p, [selector.value])}

    # Intent axis: a separate selection dimension consumed by IntentService, not
    # a plugin category. Collect raw typology codes; format is validated here,
    # typology membership + expansion + detectorless filtering happen later in
    # IntentService. When no intent: selector is given, inject the configured
    # default (run.intent_spec) so the intent scope survives a run.spec override.
    from garak import _config
    from garak.services.intentservice import validate_intent_specifier

    intent_includes = [s.value for s in spec.include if s.kind == "intent"]
    intent_excludes = [s.value for s in spec.exclude if s.kind == "intent"]
    for code in intent_includes + intent_excludes:
        # ``*`` / ``all`` select every intent (IntentService expands the vacuous
        # sentinel); other codes must match the typology specifier format.
        if code.lower() in ("*", "all"):
            continue
        if not validate_intent_specifier(code):
            rejected.append(f"intent:{code}")
    intents_explicit = bool(intent_includes or intent_excludes)
    if intent_includes:
        intents = list(dict.fromkeys(intent_includes))
    else:
        default = getattr(_config.run, "intent_spec", None)
        intents = [c.strip() for c in str(default).split(",") if c.strip()] if default else []

    rejected = sorted(set(rejected))
    inactive_modules = sorted(set(inactive_modules))
    if rejected and not skip_unknown:
        raise ValueError(f"unknown run.spec selectors: {rejected}")

    # an explicit ``none`` selection is intentionally empty, not an error
    if candidate or probe_none:
        empty_reason = None
    elif inactive_modules:
        names = ", ".join(inactive_modules)
        empty_reason = (
            f"all plugins in '{names}' are marked inactive; select one or more "
            f"by name (e.g. {inactive_modules[0]}.<ClassName>) to continue"
        )
    else:
        empty_reason = _empty_reason(spec)
    return _spec.Resolution(
        selected={"probes": sorted(candidate), "buffs": sorted(buffs)},
        rejected=rejected,
        inactive=inactive_modules,
        empty_reason=empty_reason,
        intents=intents,
        blocked_intents=list(dict.fromkeys(intent_excludes)),
        intents_explicit=intents_explicit,
    )
