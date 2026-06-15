# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unified ``run.spec`` selection grammar.

A single internal :class:`Spec` (a list of :class:`Selector` with explicit
polarity) is produced by two transports that parse to the same object:

* CLI string (comma separated), via :func:`parse_spec_string`
* config file form (YAML/JSON ``include``/``exclude`` lists), via
  :func:`parse_spec_file`

This module covers the grammar: parsing and serialisation. Resolving a
:class:`Spec` to concrete plugin names (against active/tier/tag state) lives in
:func:`garak._selection.resolve_spec`; the ``parse_plugin_spec`` detector
adapter shares the same resolution core.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

# Plugin categories selectable via run.spec. Detectors are not selectable here
# yet; they keep their own legacy spec surface (parse_plugin_spec).
_CATEGORIES = ("probes", "buffs")


@dataclass(frozen=True)
class Selector:
    """A single selection clause.

    ``kind`` is one of ``"plugin_path"``, ``"none"``, ``"tag"``, ``"tier"`` or
    ``"intent"``. For ``plugin_path`` and ``none`` selectors ``value`` carries
    the category-prefixed token (e.g. ``"probes.dan"`` / ``"probes.none"``) and
    ``category`` is set; for ``tag``/``tier``/``intent`` the selector applies to
    a non-plugin axis and ``category`` is ``None`` (``tag``/``tier`` filter
    probes; ``intent`` carries a raw typology code for IntentService). A
    ``none`` selector is an explicit empty selection for its category, distinct
    from an unspecified spec (which defaults to all active probes at resolve
    time).
    """

    kind: str
    value: str
    include: bool = True
    category: Optional[str] = None


@dataclass
class Spec:
    """Internal representation of a unified selection spec."""

    include: List[Selector] = field(default_factory=list)
    exclude: List[Selector] = field(default_factory=list)

    def to_file_dict(self) -> dict:
        """Serialise to the config-file form (``include``/``exclude`` lists)."""

        def _token(selector: Selector):
            if selector.kind in ("plugin_path", "none"):
                return selector.value
            return {selector.kind: selector.value}

        return {
            "include": [_token(s) for s in self.include],
            "exclude": [_token(s) for s in self.exclude],
        }


@dataclass
class Resolution:
    """Resolved selection.

    ``selected`` maps each plugin category to its canonical
    ``category.module.Class`` names (e.g. ``{"probes": [...], "buffs": [...]}``);
    a further category can be added without changing this type. ``rejected``
    lists unknown selectors; ``inactive`` lists bare-module selectors that exist
    but whose plugins are all inactive (known-but-empty, distinct from unknown -
    see issue #830); ``empty_reason`` is set when the spec resolves to no probes.
    ``probes`` and ``buffs`` are convenience accessors over ``selected``.

    The intent axis is separate: ``intents``/``blocked_intents`` are raw typology
    codes (IntentService expands and detectorless-filters them); ``intents`` may
    be the injected ``run.intent_spec`` default. ``intents_explicit`` flags a
    user-supplied ``intent:`` (vs the default) to warn when no ``IntentProbe`` is
    selected."""

    selected: Dict[str, List[str]]
    rejected: List[str]
    inactive: List[str] = field(default_factory=list)
    empty_reason: Optional[str] = None
    intents: List[str] = field(default_factory=list)
    blocked_intents: List[str] = field(default_factory=list)
    intents_explicit: bool = False

    @property
    def probes(self) -> List[str]:
        return self.selected.get("probes", [])

    @property
    def buffs(self) -> List[str]:
        return self.selected.get("buffs", [])


def parse_spec_string(spec: str) -> Spec:
    """Parse the CLI string transport into a :class:`Spec`.

    Selectors are comma separated; a leading ``-`` excludes, ``+`` (or no
    prefix) includes. Inter-selector whitespace is rejected (outer whitespace is
    stripped, blank clauses tolerated) so the comma list needs no shell quoting;
    a ``*`` glob still does. Dedup is implicit at resolve time.
    """
    out = Spec()
    text = (spec or "").strip()
    if any(ch.isspace() for ch in text):
        raise ValueError(
            "run.spec must not contain whitespace between selectors; separate "
            "them with commas only, e.g. "
            "'probes.dan,-probes.dan.DanInTheWild,tag:owasp:llm01'"
        )
    for raw in text.split(","):
        if not raw:
            continue
        include = not raw.startswith("-")
        token = raw.lstrip("+-")
        if not token:
            continue
        (out.include if include else out.exclude).append(_classify(token, include))
    return out


def parse_spec_file(node: Optional[dict]) -> Spec:
    """Parse the config-file transport (``{"include": [...], "exclude": [...]}``).

    List items are either plugin-path strings (``"probes.dan"``) or single-key
    mappings for filters (``{"tag": "owasp:llm01"}``, ``{"tier": 1}``).
    """
    out = Spec()
    if not node:
        return out
    for polarity, bucket in (("include", out.include), ("exclude", out.exclude)):
        for item in node.get(polarity) or []:
            if not isinstance(item, str):
                if not isinstance(item, dict) or len(item) != 1:
                    raise ValueError(
                        f"run.spec item must be a string or single-key mapping: {item!r}"
                    )
                (key, value), = item.items()
                item = f"{key}:{value}"
            bucket.append(_classify(item, polarity == "include"))
    return out


def _classify(token: str, include: bool) -> Selector:
    """Turn a bare token (polarity already stripped) into a :class:`Selector`."""
    if token.startswith("tag:"):
        return Selector("tag", token[4:], include, None)
    if token.startswith("tier:"):
        return Selector("tier", _normalize_tier(token[5:]), include, None)
    # intent typology code (e.g. ``intent:S``, ``intent:S001``, ``intent:S001mis``),
    # or ``intent:*`` / ``intent:all`` for every intent. A run.spec axis consumed by
    # IntentService, not a plugin selection; format is validated at resolve time,
    # typology membership at IntentService load. One code per selector: a
    # comma-separated value (e.g. an old ``cas.intent_spec: "S004,S005"`` string)
    # is a syntax error -- use one ``intent:`` per code.
    if token.startswith("intent:"):
        value = token[7:].strip()
        if "," in value:
            raise ValueError(
                f"run.spec intent selector {value!r}: use one intent: per code "
                f"(e.g. 'intent:S004, intent:S005'), not a comma-separated value"
            )
        return Selector("intent", value, include, None)
    # explicit empty selection: bare ``none`` (probes) or ``<category>.none``
    # selects nothing for that category, distinct from an unspecified spec.
    if token.lower() == "none":
        return Selector("none", "probes.none", include, "probes")
    # bare ``all``/``*`` selects all active probes, mirroring the legacy spec
    # where the two were identical; normalised to the canonical ``probes.*``.
    if token.lower() in ("all", "*"):
        return Selector("plugin_path", "probes.*", include, "probes")
    category = token.split(".", 1)[0]
    if category not in _CATEGORIES:
        raise ValueError(
            f"run.spec selector {token!r}: category prefix must be one of "
            f"{_CATEGORIES}"
        )
    if token.lower() == f"{category}.none":
        return Selector("none", f"{category}.none", include, category)
    # ``<category>.all`` is an alias of the ``<category>.*`` glob (generic
    # across categories), normalised so serialisation keeps a single token.
    if token.lower() == f"{category}.all":
        return Selector("plugin_path", f"{category}.*", include, category)
    return Selector("plugin_path", token, include, category)


def _normalize_tier(value: str) -> str:
    """Normalise a tier value (int or Tier name) to its int as a string."""
    from garak.probes._tier import Tier

    raw = value.strip()
    try:
        number = int(raw)
    except ValueError:
        try:
            return str(Tier[raw.upper()].value)
        except KeyError as exc:
            raise ValueError(
                f"unknown tier {value!r}; use an int (1..3, 9) or a Tier name"
            ) from exc
    try:
        Tier(number)
    except ValueError as exc:
        raise ValueError(
            f"invalid tier {value!r}; use an int (1..3, 9) or a Tier name"
        ) from exc
    return str(number)


def _legacy_path_selectors(spec: Optional[str], category: str) -> List[Selector]:
    """Translate a legacy spec string (unprefixed ``dan`` / ``dan.AutoDAN`` /
    ``all`` / ``auto`` / ``none``) into :class:`Selector` objects.

    ``none`` yields an explicit empty-selection sentinel for the category,
    distinct from an unspecified spec (``None``/``""``/``auto``), which defaults
    to all active probes at resolve time."""
    if spec is None or str(spec).lower() in ("", "auto"):
        return []
    if str(spec).lower() == "none":
        return [Selector("none", f"{category}.none", True, category)]
    if str(spec).lower() in ("all", "*"):
        return [Selector("plugin_path", f"{category}.*", True, category)]
    selectors = []
    for clause in str(spec).split(","):
        clause = clause.strip()
        if not clause:
            continue
        if clause.split(".", 1)[0] in _CATEGORIES:
            raise ValueError(
                f"legacy {category} selection {clause!r} already carries a category "
                f"prefix; legacy keys take unprefixed values (e.g. 'encoding.CharCode'), "
                f"not unified run.spec tokens"
            )
        selectors.append(Selector("plugin_path", f"{category}.{clause}", True, category))
    return selectors


def legacy_selection_spec(
    probe_spec: Optional[str],
    buff_spec: Optional[str],
    probe_tags: Optional[str],
) -> Optional[dict]:
    """Build the ``run.spec`` file-form dict from the deprecated selection keys.

    Returns ``None`` when none of ``probe_spec``/``buff_spec``/``probe_tags``
    carry a meaningful value (absent / empty / ``auto``). This is the single
    mapping shared by the config-load shim
    (:func:`garak._config._map_legacy_selection`), the CLI flag handling, and
    the ``run.spec`` fixer migration."""

    def _meaningful(value) -> bool:
        return value is not None and str(value).strip().lower() not in ("", "auto")

    if not any(_meaningful(v) for v in (probe_spec, buff_spec, probe_tags)):
        return None
    include = [s.value for s in _legacy_path_selectors(probe_spec, "probes")]
    include += [s.value for s in _legacy_path_selectors(buff_spec, "buffs")]
    if _meaningful(probe_tags):
        include.append({"tag": probe_tags})
    return {"include": include, "exclude": []}
