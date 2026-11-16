"""Source intents survive task expansion, masking, and prompt pruning."""

import json

import pytest

import garak.payloads
from garak.probes.sata import MLM, _nltk_mask_payloads
from garak.probes.web_injection import TaskXSS


@pytest.fixture
def payload_groups(tmp_path, monkeypatch):
    groups = {}
    definitions = {
        "first": ("S008inject", ["Write recipe", "Write recipe soup bread"]),
        "second": ("S005hate", ["Write recipe soup bread"]),
        "missing": (None, ["Write recipe soup bread"]),
        "tasks": ("T003", ["task one", "task two"]),
        "empty": ("S001mis", []),
    }
    for name, (intent, payloads) in definitions.items():
        data = {"garak_payload_name": name, "payload_types": [], "payloads": payloads}
        if intent is not None:
            data["intent"] = intent
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        groups[name] = garak.payloads.PayloadGroup(name, path)
    monkeypatch.setattr(garak.payloads, "load", groups.__getitem__)
    monkeypatch.setattr(
        "garak.probes.sata.nltk.pos_tag",
        lambda words: [(word, "VB" if word == "Write" else "NN") for word in words],
    )
    return groups


@pytest.mark.parametrize("probe_class", [TaskXSS, MLM])
@pytest.mark.parametrize(
    "names", [["first"], ["first", "empty", "second", "missing"], ["empty"]]
)
@pytest.mark.parametrize("cap", [None, 3, 0])
def test_expanded_prompts_keep_source_intents(payload_groups, probe_class, names, cap):
    if probe_class is TaskXSS:
        options = {"payloads": names, "tasks": ["tasks"], "soft_probe_prompt_cap": cap}
        expected = [
            (
                probe_class.template.replace("{task}", task).replace(
                    "{injection_marker}", payload
                ),
                group.intent or probe_class.intent,
            )
            for task in payload_groups["tasks"].payloads
            for name in names
            for group in [payload_groups[name]]
            for payload in group.payloads
        ]
    else:
        options = {
            "payload_name": names,
            "n_replacements": 3,
            "soft_probe_prompt_cap": cap,
        }
        expected = [
            (probe_class.template.format(payload), group.intent or probe_class.intent)
            for name in names
            for group in [payload_groups[name]]
            for payload in _nltk_mask_payloads(group.payloads, n=3)
        ]
    module = probe_class.__module__.split(".")[-1]
    probe = probe_class(
        config_root={"probes": {module: {probe_class.__name__: options}}}
    )
    if probe_class is MLM and cap is not None:
        probe._prune_data(cap)
    actual = [
        (prompt, probe._mint_attempt(prompt, seq).intent)
        for seq, prompt in enumerate(probe.prompts)
    ]
    assert len(probe._prompt_intents) == len(
        probe.prompts
    ), "retain aligned intent metadata"
    expected_count = len(expected) if cap is None else min(len(expected), cap)
    assert len(actual) == expected_count, "honour the requested cap"
    if cap is None:
        assert (
            actual == expected
        ), "preserve prompt order, duplicates and each source intent"
    else:
        # Remove matches individually so identical prompts from different groups
        # cannot conceal lost source associations.
        remaining = expected.copy()
        for pair in actual:
            assert pair in remaining, "pruning must preserve the prompt's source intent"
            remaining.remove(pair)


def test_sata_masking_counts(payload_groups):
    probe = MLM(
        config_root={
            "probes": {
                "sata": {
                    "MLM": {
                        "payload_name": ["first", "second", "missing"],
                        "n_replacements": 3,
                    }
                }
            }
        }
    )
    assert (
        probe._prompt_intents == ["S008inject"] * 3 + ["S005hate"] * 3 + [None] * 3
    ), "zero variants add no intent; every masked variant inherits its source"
