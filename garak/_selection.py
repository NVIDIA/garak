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
from garak.cas import get_parent_name

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
        body = token[len(prefix) :] if token.startswith(prefix) else token
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


def _intent_under(code: str, codes: List[str]) -> bool:
    """True if ``code`` or a typology ancestor is in ``codes``; malformed codes never match."""
    current: str = code
    while current:
        if current in codes:
            return True
        try:
            current = get_parent_name(current)
        except ValueError:
            return False
    return False


def _intent_keeps(name: str, includes: List[str], excludes: List[str]) -> bool:
    """True if ``name`` survives the intent filter. A probe declaring no intent
    (an IntentProbe, by convention) is kept unless its ``blocked_intent_spec``
    covers every included code, in which case it has nothing left to serve."""
    info = _plugins.plugin_info(name)
    code = info.get("intent")
    if code is None:
        blocked_spec = info.get("blocked_intent_spec", "")
        blocked = [c.strip() for c in blocked_spec.split(",") if c.strip()]
        return not (blocked and all(_intent_under(inc, blocked) for inc in includes))
    return _intent_under(code, includes) and not _intent_under(code, excludes)


def _intent_excluded(name: str, excludes: List[str]) -> bool:
    """True if ``name`` declares its own intent and it descends from an
    excluded code. Used for exclude-only specs (no explicit ``intent:``
    include): pruning here compares each probe's own declared intent against
    the excludes, so it never depends on the injected default scope. An
    ``IntentProbe`` (no declared intent) is never excluded here; which
    intents it actually serves is decided later by IntentService."""
    code = _plugins.plugin_info(name).get("intent")
    return code is not None and _intent_under(code, excludes)


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
    intent_codes = [
        s.value
        for s in spec.include
        if s.kind == "intent" and s.value.lower() not in ("*", "all")
    ]
    if intent_codes:
        codes = ", ".join(intent_codes)
        return (
            f"no selected probe carries intent '{codes}'; widen the probe "
            f"selection or drop the intent selector"
        )
    excluded_intent_codes = [
        s.value
        for s in spec.exclude
        if s.kind == "intent" and s.value.lower() not in ("*", "all")
    ]
    if excluded_intent_codes:
        codes = ", ".join(excluded_intent_codes)
        return (
            f"every selected probe's intent falls under the excluded code(s) "
            f"'{codes}'; narrow the exclusion or widen the probe selection"
        )
    if any(s.kind in ("tag", "tier") for s in spec.include):
        return "no active probe matches the given tier/tag filters; widen the filters"
    return "every included probe was removed by an exclusion; adjust includes/excludes"


def resolve_spec(spec: _spec.Spec, skip_unknown: bool = False) -> _spec.Resolution:
    """Resolve a :class:`garak._spec.Spec` to concrete probe and buff names.

    Selection happens against the live plugin registry (active state, tiers,
    tags). An explicit ``intent:`` include additionally filters probes by
    typology descendancy; the injected default scope never filters, and
    ``IntentProbe`` subclasses are pruned only when their
    ``blocked_intent_spec`` covers every included code. A lone ``-intent:``
    (no include) also prunes: probes whose own declared intent descends from
    an excluded code drop out of the already-resolved candidate set. This is
    the single entry point used by the CLI and harnesses.
    """
    rejected: List[str] = []
    inactive_modules: List[str] = []

    # Layer 1: probe candidate set from plugin-path includes; default probes.*
    # unless an explicit ``none`` selector requests an empty probe selection.
    probe_includes = [
        s for s in spec.include if s.kind == "plugin_path" and s.category == "probes"
    ]
    probe_none = any(s.kind == "none" and s.category == "probes" for s in spec.include)
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

    # Intent filter, mirroring the tag filter's OR-of-prefixes shape but matching
    # by typology descendancy. An explicit intent: include filters the candidate
    # set by descendancy (injected DEFAULT_INTENT_SCOPE never prunes);
    # intent:* / intent:all are vacuous and do not filter. A probe that declares
    # no intent (an IntentProbe, by convention) is pruned only when its
    # blocked_intent_spec covers every included code; otherwise which intents it
    # actually serves is decided later by IntentService. A lone -intent:
    # (no include) also prunes: any already-selected probe whose own declared
    # intent descends from an excluded code drops out, compared against the
    # resolved candidate set rather than the injected default scope.
    intent_includes = [s.value for s in spec.include if s.kind == "intent"]
    intent_excludes = [s.value for s in spec.exclude if s.kind == "intent"]
    # Malformed codes must not drive pruning: they stay in ``rejected`` (raised
    # below unless ``skip_unknown``), so a bad code never silently narrows the
    # preview to IntentProbe-only under ``--list_probes``.
    intent_filter = [
        c
        for c in intent_includes
        if c.lower() not in ("*", "all") and _spec.validate_intent_specifier(c)
    ]
    intent_exclude_filter = [
        c
        for c in intent_excludes
        if c.lower() not in ("*", "all") and _spec.validate_intent_specifier(c)
    ]
    if intent_filter:
        candidate = {
            p
            for p in candidate
            if _intent_keeps(p, intent_filter, intent_exclude_filter)
        }
    elif intent_exclude_filter:
        candidate = {
            p for p in candidate if not _intent_excluded(p, intent_exclude_filter)
        }

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
                logging.debug("run.spec: no active probe of tier %s to remove", number)
            candidate -= removed
        elif selector.kind == "tag":
            candidate = {p for p in candidate if not _has_any_tag(p, [selector.value])}

    # Intent axis: a separate selection dimension consumed by IntentService, not
    # a plugin category. Collect raw typology codes; format is validated here,
    # typology membership + expansion + detectorless filtering happen later in
    # IntentService. When no intent: selector is given, inject the default scope
    # (_spec.DEFAULT_INTENT_SCOPE) so the intent scope survives a run.spec override.
    for code in intent_includes + intent_excludes:
        # ``*`` / ``all`` select every intent (IntentService expands the vacuous
        # sentinel); other codes must match the typology specifier format.
        if code.lower() in ("*", "all"):
            continue
        if not _spec.validate_intent_specifier(code):
            rejected.append(f"intent:{code}")
    intents_explicit = bool(intent_includes or intent_excludes)
    if intent_includes:
        intents = list(dict.fromkeys(intent_includes))
    else:
        intents = [
            c.strip() for c in _spec.DEFAULT_INTENT_SCOPE.split(",") if c.strip()
        ]

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
