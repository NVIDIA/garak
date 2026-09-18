# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Wiring between the run.spec ``intent:`` axis and the IntentService.

The CLI stashes the resolved intent codes on ``_config.transient``; IntentService
reads them at ``load()`` and performs typology expansion + detectorless filtering.
"""

import pytest

import garak._config
import garak.services.intentservice as intentservice
from garak.exception import GarakException


@pytest.fixture(autouse=True)
def _reset_intent_transient():
    garak._config.load_config()
    yield
    garak._config.transient.intent_spec = None
    garak._config.transient.blocked_intent_spec = None
    garak._config.transient.intents_explicit = False


def _load(intent_spec=None, blocked_spec=None):
    garak._config.transient.intent_spec = intent_spec
    garak._config.transient.blocked_intent_spec = blocked_spec
    intentservice.load()
    return intentservice.intents_active


def test_resolved_intents_drive_active():
    active = _load("S004")
    assert active, "resolved intent:S004 must populate active intents"
    assert all(
        code.startswith("S004") for code in active
    ), "only the S004 subtree should be active for intent:S004"


def test_blocked_intent_removed():
    active = _load("S005", "S005profanity")
    assert "S005profanity" not in active, "-intent:S005profanity must drop that code"
    assert "S005hate" in active, "sibling S005 codes remain after blocking profanity"


def test_default_fallback_when_transient_unset():
    # transient unset -> fall back to DEFAULT_INTENT_SCOPE (S)
    fallback = _load(None)
    explicit_s = _load("S")
    assert fallback == explicit_s, "unset transient must fall back to DEFAULT_INTENT_SCOPE (S)"
    assert fallback, "default S scope must resolve to a non-empty active set"


def test_nonexistent_code_fails_closed():
    with pytest.raises(GarakException, match="not in the loaded intent typology"):
        _load("S999")


def test_serve_detectorless_flag_governs_expansion():
    garak._config.run.serve_detectorless_intents = False
    assert _load("S001") == set(), "S001 is detectorless; dropped by default"
    garak._config.run.serve_detectorless_intents = True
    assert "S001mis" in _load("S001"), "serve_detectorless_intents keeps detectorless S001 codes"


def test_all_intents_selector_spans_branches():
    # intent:* / intent:all -> IntentService expands the vacuous sentinel to every
    # intent (then detectorless-filtered), spanning branches beyond S.
    active = _load("*")
    assert active, "intent:* selects every intent (after detectorless filter)"
    assert "M010" in active, "all-intents spans branches beyond Safety (e.g. M010)"


def test_empty_axis_yields_no_prompts():
    # intent:S004 then -intent:S004 -> exclude wins -> empty active-intent set.
    # The IntentProbe must build no prompts and not crash (graceful no-op, 3A).
    import garak._plugins

    assert _load("S004", "S004") == set(), "exclude of the included code empties the axis"
    probe = garak._plugins.load_plugin("probes.base.IntentProbe")
    assert probe.prompts == [], "empty intent axis yields an IntentProbe with no prompts"


# The "intent: without consumer" warning lives once at orchestration (command),
# over the whole probe selection -- not in the per-probe Harness.run() loop, which
# would false-positive on the non-IntentProbe calls of a mixed selection.
def test_warn_unconsumed_intents_fires_without_intent_probe(capsys):
    import garak.command as command

    # probes.base.Probe declares no intent of its own (unlike e.g. dan.* probes,
    # which default to T009ignore) -- nothing here engages the intent axis at all.
    garak._config.transient.intents_explicit = True
    command.warn_unconsumed_intents(["probes.base.Probe"])
    out = capsys.readouterr().out
    assert (
        "no IntentProbe is selected" in out
    ), "explicit intent: with no IntentProbe in the selection must warn"
    assert (
        "no intent-derived prompts will be generated" in out
    ), "the warning states no intent-derived prompts result without an IntentProbe"
    # the message must not assert narrowing, since intent:*/intent:all and some
    # exclude-only specs never prune the probe set
    assert "narrowed" not in out, "the warning must not claim narrowing"


def test_warn_unconsumed_intents_silent_with_mixed_selection(capsys):
    import garak.command as command

    # an IntentProbe alongside a regular probe must NOT warn (the per-probe harness
    # location used to false-positive on the regular probe here)
    garak._config.transient.intents_explicit = True
    command.warn_unconsumed_intents(
        ["probes.grandma.GrandmaIntent", "probes.dan.DanInTheWild"]
    )
    assert capsys.readouterr().out == "", "an IntentProbe in the selection consumes intents"


def test_warn_unconsumed_intents_silent_when_default(capsys):
    import garak.command as command

    garak._config.transient.intents_explicit = False
    command.warn_unconsumed_intents(["probes.dan.DanInTheWild"])
    assert capsys.readouterr().out == "", "the injected default (not explicit) must not warn"


def test_warn_rejected_selectors_reports_each(capsys):
    # generic reporter for any run.spec selector dropped under skip_unknown=True
    # (e.g. a malformed intent: code in a --list_probes/--list_buffs preview).
    import garak.command as command

    command.warn_rejected_selectors(["intent:zzz", "probes.nonexistent"], "probes")
    out = capsys.readouterr().out
    assert "intent:zzz" in out, "each rejected selector must be named in the warning"
    assert (
        "probes.nonexistent" in out
    ), "each rejected selector must be named in the warning"


def test_warn_rejected_selectors_silent_when_empty(capsys):
    import garak.command as command

    command.warn_rejected_selectors([], "buffs")
    assert capsys.readouterr().out == "", "no rejected selectors must print nothing"


def test_probe_pruning_does_not_change_active_intent_set():
    # the probe-selection filter and the IntentService active set are independent
    # axes: filtering the probe set must not change which intents become active.
    from garak._selection import resolve_spec
    from garak._spec import parse_spec_string

    res = resolve_spec(parse_spec_string("probes.*,intent:S005hate"))
    assert res.intents == [
        "S005hate"
    ], "the intent axis carries the requested code regardless of probe pruning"
    active = _load("S005hate")
    assert (
        "S005hate" in active
    ), "the active intent set derives from the code, not from surviving probes"

