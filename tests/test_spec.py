# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the unified ``run.spec`` selection grammar (garak._spec)."""

import pytest

from garak._plugins import enumerate_plugins, plugin_info
from garak._selection import resolve_spec
from garak._spec import parse_spec_string, parse_spec_file


def _active(category):
    return {name for name, active in enumerate_plugins(category=category) if active}


def _one_inactive(category):
    for name, active in enumerate_plugins(category=category):
        if not active:
            return name
    return None


def _tier(name):
    return int(plugin_info(name).get("tier", 9))


def resolve(spec_str, **kwargs):
    return resolve_spec(parse_spec_string(spec_str), **kwargs)


# --- T1: polarity ---------------------------------------------------------


def test_polarity_bare_plus_equivalent():
    bare = set(resolve("probes.dan").probes)
    plus = set(resolve("+probes.dan").probes)
    assert bare == plus, "bare and '+' selectors must include identically"
    assert bare, "probes.dan family should resolve to at least one active probe"


def test_polarity_minus_excludes():
    family = set(resolve("probes.dan").probes)
    minus = set(resolve("probes.dan,-probes.dan.DanInTheWild").probes)
    assert minus < family, "'-' must remove DanInTheWild from the dan family"
    assert "probes.dan.DanInTheWild" not in minus, "excluded class must be absent"


# --- T2: plugin path forms ------------------------------------------------


def test_plugin_path_glob_is_all_active():
    assert set(resolve("probes.*").probes) == _active(
        "probes"
    ), "probes.* must resolve to all active probes"


def test_plugin_path_family_and_class():
    family = set(resolve("probes.dan").probes)
    assert all(
        p.startswith("probes.dan.") for p in family
    ), "family selector must only yield dan.* probes"
    one = resolve("probes.dan.DanInTheWild").probes
    assert one == ["probes.dan.DanInTheWild"], "explicit class must resolve to itself"


# --- T2b: 'all' is an alias of '*' ----------------------------------------


def test_all_alias_equals_star_probes():
    assert (
        set(resolve("probes.all").probes)
        == set(resolve("probes.*").probes)
        == _active("probes")
    ), "probes.all must equal probes.* (all active probes)"


def test_all_alias_equals_star_buffs():
    assert (
        set(resolve("buffs.all").buffs)
        == set(resolve("buffs.*").buffs)
        == _active("buffs")
    ), "buffs.all must equal buffs.* (alias is generic across categories)"


def test_bare_all_and_star_are_probes_star():
    star = set(resolve("probes.*").probes)
    assert set(resolve("all").probes) == star, "bare 'all' must behave as probes.*"
    assert set(resolve("*").probes) == star, "bare '*' must behave as probes.*"


def test_all_serialises_to_canonical_star():
    assert parse_spec_string("probes.all").to_file_dict()["include"] == [
        "probes.*"
    ], "all must normalise to the canonical '*' token on serialisation"


def test_all_plus_explicit_inactive_class():
    inactive = _one_inactive("probes")
    assert inactive, "fixture expects at least one inactive probe to exist"
    res = set(resolve(f"probes.all,{inactive}").probes)
    assert _active("probes") <= res, "probes.all must keep every active probe"
    assert inactive in res, "explicit inactive class must be added alongside all-active"


def test_inactive_only_module_flagged_alongside_active(capsys):
    # issue #830: an all-inactive module selected with an active one must be
    # surfaced via Resolution.inactive, not silently dropped
    res = resolve("probes.dan,probes.test", skip_unknown=True)
    assert res.probes, "the active family must still resolve"
    assert "probes.test" in res.inactive, "all-inactive module must be flagged as inactive"
    assert "probes.test" not in res.rejected, "inactive module is known, not unknown"


def test_negative_all_removes_all_probes():
    assert resolve("-probes.all").probes == [], "-probes.all must remove every probe"
    assert (
        resolve("-probes.all").probes == resolve("-probes.*").probes
    ), "-probes.all must behave exactly like -probes.*"


def test_negative_buffs_all_equals_star():
    minus_all = resolve("probes.lmrc.Bullying,buffs.all,-buffs.all")
    minus_star = resolve("probes.lmrc.Bullying,buffs.*,-buffs.*")
    assert minus_all.buffs == [] == minus_star.buffs, "-buffs.all must clear all buffs like -buffs.*"


def test_all_as_class_segment_is_literal_not_glob():
    res = resolve("probes.all.Something", skip_unknown=True)
    assert res.probes == [], "probes.all.Something is a literal unknown class, not a glob"
    assert (
        "probes.all.Something" in res.rejected
    ), "an unknown literal class must be rejected, not silently globbed"


def test_all_via_file_transport():
    spec = parse_spec_file(
        {"include": ["probes.all", "buffs.all"], "exclude": ["probes.dan.DanInTheWild"]}
    )
    res = resolve_spec(spec)
    assert set(res.probes) == _active("probes") - {
        "probes.dan.DanInTheWild"
    }, "file-form 'probes.all' must select all active probes (minus the excluded class)"
    assert set(res.buffs) == _active(
        "buffs"
    ), "file-form 'buffs.all' must select all active buffs"


# --- T3: buffs ------------------------------------------------------------


def test_buffs_selected_and_no_default():
    res = resolve("probes.dan,buffs.lowercase")
    assert "buffs.lowercase.Lowercase" in res.buffs, "buffs.lowercase must select the buff"
    assert resolve("probes.dan").buffs == [], "no buffs by default"


# --- T4: tag filter -------------------------------------------------------


def test_tag_is_filter_intersection():
    res = set(resolve("probes.grandma,tag:owasp:llm06").probes)
    family = set(resolve("probes.grandma").probes)
    assert res <= family, "tag: must narrow, not expand the family"
    assert res, "grandma should have probes tagged owasp:llm06"
    assert all(
        any(t.startswith("owasp:llm06") for t in plugin_info(p).get("tags", []))
        for p in res
    ), "every surviving probe must carry the owasp:llm06 tag"


def test_tag_multiple_is_or():
    a = set(resolve("probes.grandma,tag:owasp:llm06").probes)
    b = set(resolve("probes.grandma,tag:risk-cards").probes)
    both = set(resolve("probes.grandma,tag:owasp:llm06,tag:risk-cards").probes)
    assert both == (a | b), "multiple tags must combine as OR"


# --- T5: tier filter (log-level) ------------------------------------------


def test_tier_log_level_is_cumulative():
    t1 = set(resolve("tier:1").probes)
    t2 = set(resolve("tier:2").probes)
    t3 = set(resolve("tier:3").probes)
    assert t1 <= t2 <= t3, "tier:N must be cumulative (1..N)"
    assert all(_tier(p) <= 2 for p in t2), "tier:2 must only contain tiers 1..2"


def test_tier_multiple_takes_widest():
    assert set(resolve("tier:1,tier:3").probes) == set(
        resolve("tier:3").probes
    ), "multiple tier: selectors take the widest (max)"


def test_tier_negative_removes_exact_tier():
    base = set(resolve("tier:3").probes)
    minus = set(resolve("tier:3,-tier:2").probes)
    assert minus == {p for p in base if _tier(p) != 2}, "-tier:2 removes exactly tier 2"


def test_tier_name_equals_int():
    assert set(resolve("tier:of_concern").probes) == set(
        resolve("tier:1").probes
    ), "tier:of_concern must equal tier:1"


@pytest.mark.parametrize("bad", ["tier:99", "tier:notatier"])
def test_tier_invalid_raises(bad):
    with pytest.raises(ValueError):
        parse_spec_string(f"probes.*,{bad}")


# --- empty-result detection -----------------------------------------------


def test_tier_contradiction_empty_with_reason():
    # ansiescape.AnsiEscaped is an active tier-3 probe; tier:1 admits only tier 1
    res = resolve("probes.ansiescape.AnsiEscaped,tier:1")
    assert res.probes == [], "tier:1 must drop a tier-3 explicit class"
    assert res.empty_reason and "tier" in res.empty_reason, "reason must name the tier conflict"


def test_fully_excluded_include_empty_with_reason():
    res = resolve("probes.dan,-probes.dan")
    assert res.probes == [], "excluding the included family yields empty"
    assert res.empty_reason, "empty result must carry a reason"


def test_none_selects_no_probes():
    res = resolve("probes.none")
    assert res.probes == [], "probes.none must select no probes"
    assert (
        res.empty_reason is None
    ), "explicit none is intentionally empty, not an error"


def test_bare_none_is_probes_none():
    assert resolve("none").probes == resolve("probes.none").probes == [], (
        "bare 'none' must behave as probes.none (empty selection)"
    )


def test_none_distinct_from_unspecified():
    assert set(resolve("").probes) == _active("probes"), "unspecified -> all active"
    assert resolve("none").probes == [], "none -> empty, not the default-all universe"


def test_none_round_trips_through_file_form():
    from_cli = parse_spec_string("none")
    round_trip = parse_spec_file(from_cli.to_file_dict())
    assert from_cli.to_file_dict()["include"] == [
        "probes.none"
    ], "none must serialise to the 'probes.none' token"
    assert (
        resolve_spec(round_trip).probes == []
    ), "none must still resolve to no probes after a file round-trip"


def test_legacy_none_maps_to_empty_selection():
    from garak._spec import _legacy_path_selectors

    selectors = _legacy_path_selectors("none", "probes")
    assert [s.kind for s in selectors] == [
        "none"
    ], "legacy 'none' must yield a single none selector"
    assert (
        _legacy_path_selectors(None, "probes") == []
    ), "unspecified legacy spec must yield no selectors (defaults to all)"


# --- T8: prefix required / scope ------------------------------------------


def test_prefix_required():
    with pytest.raises(ValueError, match="category prefix"):
        parse_spec_string("dan")


@pytest.mark.parametrize("token", ["detectors.always.Pass"])
def test_out_of_scope_kinds_raise(token):
    with pytest.raises(ValueError):
        parse_spec_string(token)


@pytest.mark.parametrize("code", ["S", "S001", "S001mis"])
def test_intent_classify(code):
    (selector,) = parse_spec_string(f"intent:{code}").include
    assert selector.kind == "intent", "intent: token must classify as the intent kind"
    assert selector.value == code, "intent value must be the raw typology code"
    assert selector.category is None, "intent is a non-plugin axis (no category)"


def test_intent_round_trip():
    spec = parse_spec_string("intent:S004,-intent:S005profanity")
    assert spec.to_file_dict() == {
        "include": [{"intent": "S004"}],
        "exclude": [{"intent": "S005profanity"}],
    }, "intent selectors must serialise to single-key {intent: code} mappings"
    again = parse_spec_file(spec.to_file_dict())
    assert (again.include[0].kind, again.include[0].value) == ("intent", "S004")
    assert (again.exclude[0].kind, again.exclude[0].value) == ("intent", "S005profanity")


def test_intent_default_injected_when_absent():
    res = resolve("probes.dan")
    assert res.intents == ["S"], "DEFAULT_INTENT_SCOPE must be injected when no intent: given"
    assert res.intents_explicit is False, "injected default is not an explicit intent selection"


def test_intent_explicit_overrides_default():
    res = resolve("probes.dan,intent:S004,-intent:S005profanity")
    assert res.intents == ["S004"], "explicit intent: replaces the injected default"
    assert res.blocked_intents == ["S005profanity"], "-intent: codes recorded as blocked"
    assert res.intents_explicit is True, "user-supplied intent: marks the selection explicit"


def test_intent_default_does_not_filter_probe_set():
    # the injected default scope (no explicit intent:) never prunes on its own.
    family = {p for p in _active("probes") if p.startswith("probes.dan.")}
    injected_default = set(resolve("probes.dan").probes)
    assert (
        injected_default == family
    ), "the injected default scope must not prune probes"


def test_intent_exclude_only_ignores_unrelated_code():
    # an exclude-only spec is a no-op when the excluded code doesn't match any
    # selected probe's own intent -- S004 is unrelated to dan's T009ignore.
    family = {p for p in _active("probes") if p.startswith("probes.dan.")}
    exclude_only = set(resolve("probes.dan,-intent:S004").probes)
    assert (
        exclude_only == family
    ), "an exclude-only intent spec must not prune probes it doesn't match"


def test_intent_exclude_only_prunes_matching_probes():
    # unlike an unrelated exclude, -intent: alone still prunes when it matches
    # a probe's own declared intent, compared against the already-resolved
    # candidate set -- it does not depend on the injected default scope. Every
    # active probes.dan.* class declares T009ignore, a child of T009.
    family = {p for p in _active("probes") if p.startswith("probes.dan.")}
    assert family, "fixture expects at least one active probes.dan.* plugin"
    pruned = set(resolve("probes.dan,-intent:T009").probes)
    assert (
        pruned == set()
    ), "-intent:T009 must remove every dan.* probe, all of which descend from T009"


def test_intent_descendancy_keeps_child_of_branch():
    probes = set(resolve("probes.*,intent:S005").probes)
    assert (
        "probes.lmrc.Bullying" in probes
    ), "intent:S005 keeps a probe declaring the child leaf S005bully"


def test_intent_leaf_drops_more_generic_probe():
    probes = set(resolve("probes.*,intent:S005hate").probes)
    assert (
        "probes.lmrc.SlurUsage" in probes
    ), "intent:S005hate keeps the probe declaring S005hate"
    assert (
        "probes.realtoxicityprompts.RTPBlank" not in probes
    ), "a leaf intent must not keep a probe declaring only the parent code S005"


def test_intent_siblings_do_not_match_by_prefix():
    # anti-regression guard: string-prefix would wrongly capture the sibling leaf
    # S001fabperson under intent:S001fab. Descendancy walks parents, so it does not.
    fab = set(resolve("probes.*,intent:S001fab").probes)
    assert (
        "probes.packagehallucination.Python" in fab
    ), "intent:S001fab keeps a probe declaring S001fab"
    assert (
        "probes.goodside.WhoIsRiley" not in fab
    ), "intent:S001fab must NOT keep the sibling leaf S001fabperson"
    parent = set(resolve("probes.*,intent:S001").probes)
    assert {
        "probes.packagehallucination.Python",
        "probes.goodside.WhoIsRiley",
    } <= parent, "intent:S001 keeps both sibling leaves S001fab and S001fabperson"


@pytest.mark.parametrize("token", ["intent:*", "intent:all"])
def test_intent_all_does_not_filter(token):
    assert set(resolve(f"probes.*,{token}").probes) == _active(
        "probes"
    ), "intent:* / intent:all is vacuous and must not prune the probe set"


def test_intent_exclude_subtracts_within_explicit_include():
    probes = set(resolve("probes.*,intent:S005,-intent:S005hate").probes)
    assert "probes.lmrc.Bullying" in probes, "S005bully stays under intent:S005"
    assert (
        "probes.lmrc.SlurUsage" not in probes
    ), "-intent:S005hate subtracts the S005hate probe while the include survives"


def test_intent_never_prunes_intent_probe_with_empty_blocked_spec():
    # GrandmaIntent's blocked_intent_spec is "" (blocks nothing), so it can never
    # cover an include code: which intents it serves is IntentService's decision,
    # made after resolution. Also the #1889 self-cancelling-axis boundary case.
    probes = set(resolve("probes.grandma.GrandmaIntent,intent:M010degrade").probes)
    assert (
        "probes.grandma.GrandmaIntent" in probes
    ), "an IntentProbe with no blocked_intent_spec is never removed by the intent filter"


def test_intent_probe_pruned_when_blocked_spec_covers_every_include(monkeypatch):
    # a synthetic IntentProbe whose blocked_intent_spec fully covers the sole
    # requested include has nothing left to serve, so it drops out of selection.
    from garak import _selection

    def fake_plugin_info(name):
        if name == "probes.fake.FullyBlockedIntent":
            return {"intent": None, "blocked_intent_spec": "S005"}
        return plugin_info(name)

    monkeypatch.setattr(_selection._plugins, "plugin_info", fake_plugin_info)
    assert not _selection._intent_keeps(
        "probes.fake.FullyBlockedIntent", ["S005hate"], []
    ), "blocked_intent_spec S005 covers the include S005hate, so the probe drops out"
    assert _selection._intent_keeps(
        "probes.fake.FullyBlockedIntent", ["S004"], []
    ), "blocked_intent_spec S005 does not cover the unrelated include S004"


def test_intent_collapse_names_codes_in_empty_reason():
    res = resolve("probes.lmrc,intent:M010degrade")
    assert (
        not res.probes
    ), "no lmrc probe carries M010degrade, so the selection collapses"
    assert (
        res.empty_reason and "M010degrade" in res.empty_reason
    ), "empty_reason names the requested intent code"
    assert (
        "intent" in res.empty_reason
    ), "reason must read as an intent collapse, not a tier collapse"


def test_intent_partial_unmatched_is_silent():
    # a valid explicit intent: that matches nothing, with the selection surviving
    # via another code, produces no field/warning -- by symmetry with tag:.
    matched = set(resolve("probes.*,intent:S005hate").probes)
    partial = resolve("probes.*,intent:S005hate,intent:M010rep")
    assert (
        set(partial.probes) == matched
    ), "an unmatched extra intent code leaves the surviving selection unchanged"
    assert partial.probes, "the selection survives via the matched code S005hate"
    assert (
        partial.empty_reason is None
    ), "a surviving partial-unmatched intent produces no empty_reason"


def test_intent_invalid_format_rejected():
    res = resolve("intent:zzz", skip_unknown=True)
    assert "intent:zzz" in res.rejected, "malformed intent code recorded in rejected"
    with pytest.raises(ValueError, match="unknown run.spec"):
        resolve("intent:zzz")


def test_intent_malformed_code_does_not_prune_candidates():
    unfiltered = set(resolve("probes.dan", skip_unknown=True).probes)
    with_malformed = set(resolve("probes.dan,intent:zzz", skip_unknown=True).probes)
    assert (
        with_malformed == unfiltered
    ), "a malformed intent: code must not drive pruning; it stays in `rejected` instead"


def test_intent_malformed_exclude_code_does_not_prune_candidates():
    unfiltered = set(resolve("probes.dan", skip_unknown=True).probes)
    with_malformed = set(resolve("probes.dan,-intent:zzz", skip_unknown=True).probes)
    assert (
        with_malformed == unfiltered
    ), "a malformed -intent: code must not drive pruning either; it stays in `rejected`"


@pytest.mark.parametrize("token", ["intent:*", "intent:all"])
def test_intent_all_selector_not_rejected(token):
    res = resolve(f"probes.dan,{token}")
    assert res.rejected == [], "intent:* / intent:all are valid (all intents), not rejected"
    assert res.intents and res.intents[0].lower() in (
        "*",
        "all",
    ), "all-intents sentinel passes through to IntentService"


def test_intent_comma_value_rejected():
    with pytest.raises(ValueError, match="one intent: per code"):
        parse_spec_file({"include": [{"intent": "S004,S005"}]})


def test_intent_exclude_only_applies_to_default():
    res = resolve("probes.dan,-intent:S004")
    assert res.intents == ["S"], "exclude-only keeps the injected default include (DEFAULT_INTENT_SCOPE)"
    assert res.blocked_intents == ["S004"], "the -intent: code is recorded as blocked"
    assert res.intents_explicit is True, "a lone -intent: still counts as an explicit intent selection"


# --- T9: unknown / skip_unknown -------------------------------------------


def test_unknown_rejected_raises_unless_skipped():
    with pytest.raises(ValueError, match="unknown run.spec"):
        resolve("probes.doesnotexist")
    res = resolve("probes.dan,probes.doesnotexist", skip_unknown=True)
    assert "probes.doesnotexist" in res.rejected, "unknown selector recorded in rejected"
    assert res.probes, "known selectors still resolve under skip_unknown"


# --- exclude wins ---------------------------------------------------------


def test_exclude_wins_over_explicit_include():
    res = resolve("probes.dan.AutoDANCached,-probes.dan")
    assert "probes.dan.AutoDANCached" not in res.probes, "exclude of family wins over explicit class"


# --- T13: implicit default ------------------------------------------------


def test_empty_string_is_probes_star():
    assert set(resolve("").probes) == _active("probes"), "empty spec -> probes.*"


def test_buff_only_keeps_default_probes():
    res = resolve("buffs.lowercase")
    assert set(res.probes) == _active("probes"), "buff-only spec keeps implicit probes.*"
    assert "buffs.lowercase.Lowercase" in res.buffs


def test_tag_only_filters_default_active():
    res = set(resolve("tag:owasp:llm06").probes)
    expected = {p for p in _active("probes") if any(t.startswith("owasp:llm06") for t in plugin_info(p).get("tags", []))}
    assert res == expected, "tag-only spec filters the default-active universe"


# --- T19: buff subtractive ------------------------------------------------


def test_buff_subtractive_all_minus_one():
    res = resolve("probes.lmrc.Bullying,buffs.*,-buffs.paraphrase")
    assert res.buffs, "buffs.* selects active buffs"
    assert not any(b.startswith("buffs.paraphrase.") for b in res.buffs), "-buffs.paraphrase removed"
    assert len(res.probes) == 1, "single probe keeps attempts low"


def test_negative_buff_alone_is_noop():
    res = resolve("-buffs.encoding")
    assert res.buffs == [], "-buffs.Y without a positive buff include is a no-op"


# --- T22: dedup / parsing robustness --------------------------------------


def test_dedup_and_blank_clauses():
    a = set(resolve("probes.dan,probes.dan,,probes.dan").probes)
    b = set(resolve("probes.dan").probes)
    assert a == b, "duplicate selectors and blank clauses are tolerated/deduplicated"


@pytest.mark.parametrize(
    "spec",
    [
        "probes.dan, probes.test",
        "probes.dan ,probes.test",
        "probes.dan,  ,probes.test",
        "tier:1, tier:2",
    ],
)
def test_whitespace_between_selectors_rejected(spec):
    with pytest.raises(ValueError, match="whitespace"):
        parse_spec_string(spec)


# --- T23: tag/tier do not affect buffs ------------------------------------


def test_tag_tier_do_not_touch_buffs():
    res = resolve("buffs.*,tag:owasp:llm01,tier:1")
    assert set(res.buffs) == _active("buffs"), "tag/tier filters must not remove buffs"


# --- T7: CLI <-> file semantic parity -------------------------------------


@pytest.mark.parametrize(
    "spec_str",
    [
        "probes.*",
        "probes.all",
        "probes.all,-probes.dan.DanInTheWild,buffs.all",
        "probes.dan,-probes.dan.DanInTheWild,buffs.encoding.Base64",
        "tier:2,tag:owasp:llm01",
        "buffs.lowercase",
        "+probes.*,+tier:3,-tier:2",
    ],
)
def test_cli_file_semantic_parity(spec_str):
    from_cli = parse_spec_string(spec_str)
    round_trip = parse_spec_file(from_cli.to_file_dict())
    cli_res, rt_res = resolve_spec(from_cli), resolve_spec(round_trip)
    assert cli_res.probes == rt_res.probes, f"probe set differs for {spec_str!r}"
    assert cli_res.buffs == rt_res.buffs, f"buff set differs for {spec_str!r}"


def test_file_mapping_form():
    spec = parse_spec_file(
        {"include": ["probes.dan", {"tag": "owasp:llm01"}], "exclude": [{"tier": 3}]}
    )
    assert any(s.kind == "tag" and s.value == "owasp:llm01" for s in spec.include)
    assert any(s.kind == "tier" and s.value == "3" for s in spec.exclude)


@pytest.mark.parametrize(
    "probe_spec, buff_spec, probe_tags, expected",
    [
        (
            "dan,lmrc",
            "lowercase",
            "owasp:llm01",
            {
                "include": [
                    "probes.dan",
                    "probes.lmrc",
                    "buffs.lowercase",
                    {"tag": "owasp:llm01"},
                ],
                "exclude": [],
            },
        ),
        ("none", None, None, {"include": ["probes.none"], "exclude": []}),
        (None, None, None, None),
        ("", "auto", "", None),
    ],
)
def test_legacy_selection_spec(probe_spec, buff_spec, probe_tags, expected):
    from garak._spec import legacy_selection_spec

    assert (
        legacy_selection_spec(probe_spec, buff_spec, probe_tags) == expected
    ), "legacy selection keys must map to the run.spec file form (or None when vacuous)"


@pytest.mark.parametrize(
    "probe_spec, buff_spec",
    [("probes.dan", None), (None, "buffs.encoding.CharCode")],
)
def test_legacy_selection_spec_rejects_category_prefixed_value(probe_spec, buff_spec):
    from garak._spec import legacy_selection_spec

    with pytest.raises(ValueError, match="already carries a category prefix"):
        legacy_selection_spec(probe_spec, buff_spec, None)
