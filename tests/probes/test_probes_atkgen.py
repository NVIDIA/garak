# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import tempfile
import importlib
from unittest.mock import patch

import garak.attempt
import garak.generators
import garak.probes.base
import pytest
from garak import _config, _plugins
from garak.exception import GarakException

ATKGEN_PROBES = ["probes.atkgen.Tox", "probes.atkgen.ToxConv"]


@pytest.mark.parametrize("plugin_name", ATKGEN_PROBES)
def test_atkgen_load(plugin_name):
    garak._config.load_config()
    p = _plugins.load_plugin(plugin_name)
    assert isinstance(p, garak.probes.base.Probe)
    for k, v in p.DEFAULT_PARAMS.items():
        if k == "red_team_model_config":
            continue
        assert getattr(p, k) == v


@pytest.mark.parametrize("plugin_name", ATKGEN_PROBES)
def test_atkgen_config(plugin_name):
    garak._config.load_config()
    p = _plugins.load_plugin(plugin_name)
    rt_mod, rt_klass = p.red_team_model_type.split(".")
    assert p.red_team_model_config == {
        "generators": {
            rt_mod: {
                rt_klass: {
                    "hf_args": {"device": "cpu", "torch_dtype": "float32"},
                    "name": p.red_team_model_name,
                }
            }
        }
    }


@pytest.mark.parametrize("plugin_name", ATKGEN_PROBES)
def test_atkgen_one_pass(plugin_name):
    _config.load_base_config()
    g = garak._plugins.load_plugin("generators.test.Repeat", config_root=garak._config)
    with tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8") as temp_report_file:
        _config.transient.reportfile = temp_report_file
        _config.transient.report_filename = temp_report_file.name
        _config.run.generations = 1
        p = _plugins.load_plugin(plugin_name, config_root=_config)
        p.max_calls_per_conv = 1  # we don't need a full conversation
        p.convs_per_generation = 1
        result = p.probe(g)
    assert isinstance(
        p.redteamer, garak.generators.base.Generator
    ), "atkgen redteamer should be a generator"
    assert isinstance(result, list), "probe results should be a list"
    assert isinstance(
        result[0], garak.attempt.Attempt
    ), "probe results should be a list of attempt.Attempt"
    assert (
        "red_team_challenge" in result[0].notes
    ), "atkgen attempts should have the challenge used to generate the prompt"


@pytest.mark.parametrize("plugin_name", ATKGEN_PROBES)
def test_atkgen_custom_model(plugin_name):
    red_team_model_type = "test.Single"
    red_team_model_name = ""
    _config.load_base_config()
    rt_custom_generator_config = {
        "probes": {
            "atkgen": {
                plugin_name.split(".")[-1]: {
                    "red_team_model_type": red_team_model_type,
                    "red_team_model_name": red_team_model_name,
                    "generations": 1,  # we only need one conversation
                }
            }
        }
    }
    p = _plugins.load_plugin(plugin_name, config_root=rt_custom_generator_config)
    p.max_calls_per_conv = 1  # we don't need a full conversation
    assert (
        p.red_team_model_type == red_team_model_type
    ), "red team model type config should be loaded"
    assert (
        p.red_team_model_name == red_team_model_name
    ), "red team model name config should be loaded"
    g = _plugins.load_plugin("generators.test.Repeat", config_root=garak._config)
    with tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8") as temp_report_file:
        _config.transient.reportfile = temp_report_file
        _config.transient.report_filename = temp_report_file.name
        result = p.probe(g)
    assert (
        p.redteamer.name == red_team_model_type.split(".")[-1]
    ), "loaded red team model name should match configured name"
    assert p.redteamer.fullname == red_team_model_type.replace(".", ":").title()


@pytest.mark.parametrize("plugin_name", ATKGEN_PROBES)
def test_atkgen_multi_conversation(plugin_name):
    _config.load_base_config()
    _config.system.verbose = 1
    _config.system.parallel_requests = 1
    _config.run.generations = 2
    klassname = plugin_name.replace("probes.", "")
    _config.plugins.probes[klassname]["max_calls_per_conv"] = 2
    _config.plugins.probes[klassname]["convs_per_generation"] = 2
    with tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8") as temp_report_file:
        _config.transient.reportfile = temp_report_file
        _config.transient.report_filename = temp_report_file.name
        _config.plugins.generators = {}
        atkgen_instance = _plugins.load_plugin(plugin_name, config_root=_config)
        generator = _plugins.load_plugin(
            "generators.test.Repeat", config_root=_config
        )  # Replace with an actual generator instance if available
        attempts = atkgen_instance.probe(generator)
        assert isinstance(
            attempts, list
        ), "probe method should return a list of attempts"
        assert len(attempts) > 0, "probe method should return at least one attempt"
        assert isinstance(
            attempts[0], garak.attempt.Attempt
        ), "probe results should be a list of attempt.Attempt"
        assert (
            "red_team_challenge" in attempts[0].notes
        ), "atkgen attempts should have the challenge used to generate the prompt"
        assert (
            len(attempts[0].prompt.turns[0].content.text) > 0
        ), "atkgen probe first prompt should not be blank"


@pytest.mark.parametrize("plugin_name", ATKGEN_PROBES)
def test_atkgen_verbose_output(capsys, plugin_name):
    """Test that verbose output (verbose >= 2) displays conversation turns correctly."""
    _config.load_base_config()
    _config.system.verbose = 2  # Enable verbose conversation output
    _config.plugins.probes["atkgen"]["generations"] = 1  # we only need one conversation
    p = _plugins.load_plugin(plugin_name, config_root=garak._config)
    p.max_calls_per_conv = 1  # we don't need a full conversation
    g = _plugins.load_plugin("generators.test.Repeat", config_root=_config)

    with tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8") as temp_report_file:
        _config.transient.reportfile = temp_report_file
        _config.transient.report_filename = temp_report_file.name
        result = p.probe(g)

    # Capture stdout
    captured = capsys.readouterr()
    output = captured.out

    # Verify verbose conversation markers are present
    assert "🆕" in output, "verbose output should contain new conversation marker"
    assert "🔴 probe:" in output, "verbose output should contain probe/challenge marker"
    assert "🦜 model:" in output, "verbose output should contain model response marker"

    # Verify that attempts were created
    assert isinstance(result, list), "probe results should be a list"
    assert len(result) > 0, "probe should return at least one attempt"


@pytest.mark.parametrize("plugin_name", ATKGEN_PROBES)
def test_atkgen_nones(plugin_name):
    _config.load_base_config()
    _config.plugins.probes["atkgen"]["generations"] = 1  # we only need one conversation
    p = _plugins.load_plugin(plugin_name, config_root=garak._config)
    p.max_calls_per_conv = 1  # we don't need a full conversation
    g = _plugins.load_plugin("generators.test.Nones", config_root=_config)

    with tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8") as temp_report_file:
        _config.transient.reportfile = temp_report_file
        _config.transient.report_filename = temp_report_file.name
        result = p.probe(g)

    assert result is not None, "Malformed None result - should be full result object"
    assert (
        len(result) == p.convs_per_generation
    ), "generators returning Nones should still give correct cardinality of results"
    assert result[0].outputs == [None], "generator Nones should be propagated back"
    assert (
        result[0].prompt.turns[0].content.text is not None
    ), "Attack text should be stored"


# ToxConv-specific tests


_TOXCONV_BASE_CONFIG = {
    "red_team_model_type": "test.Lipsum",
    "red_team_model_name": "",
}


def _make_toxconv_config(**overrides):
    cfg = dict(_TOXCONV_BASE_CONFIG)
    cfg.update(overrides)
    return {"probes": {"atkgen": {"ToxConv": cfg}}}


def _no_early_stop(attempt):
    """Stub for _should_terminate_conversation that never signals a hit."""
    return [False] * len(attempt.outputs)


def test_toxconv_invalid_branching():
    _config.load_base_config()
    with pytest.raises(GarakException, match="branching"):
        _plugins.load_plugin(
            "probes.atkgen.ToxConv",
            config_root=_make_toxconv_config(branching="diagonal"),
        )


@pytest.mark.parametrize("branching", ["linear", "branchy"])
def test_toxconv_conversation_grows(branching):
    """Each turn should extend the target conversation regardless of branching mode."""
    _config.load_base_config()
    p = _plugins.load_plugin(
        "probes.atkgen.ToxConv",
        config_root=_make_toxconv_config(branching=branching, convs_per_generation=1),
    )
    p.max_calls_per_conv = 3
    g = _plugins.load_plugin("generators.test.Lipsum", config_root=garak._config)
    with patch.object(p, "_should_terminate_conversation", side_effect=_no_early_stop):
        with tempfile.NamedTemporaryFile(
            mode="w+", encoding="utf-8"
        ) as temp_report_file:
            _config.transient.reportfile = temp_report_file
            _config.transient.report_filename = temp_report_file.name
            result = p.probe(g)

    assert len(result) > 0
    turn_lengths = [len(a.conversations[0].turns) for a in result]
    assert max(turn_lengths) > min(
        turn_lengths
    ), "later turns should have longer conversations than earlier ones"


@pytest.mark.parametrize("branching", ["linear", "branchy"])
def test_toxconv_redteamer_conversation_grows(branching):
    """The redteamer_conversation in notes should grow with each turn."""
    _config.load_base_config()
    p = _plugins.load_plugin(
        "probes.atkgen.ToxConv",
        config_root=_make_toxconv_config(branching=branching, convs_per_generation=1),
    )
    p.max_calls_per_conv = 3
    g = _plugins.load_plugin("generators.test.Lipsum", config_root=garak._config)
    with patch.object(p, "_should_terminate_conversation", side_effect=_no_early_stop):
        with tempfile.NamedTemporaryFile(
            mode="w+", encoding="utf-8"
        ) as temp_report_file:
            _config.transient.reportfile = temp_report_file
            _config.transient.report_filename = temp_report_file.name
            result = p.probe(g)

    rt_conv_lengths = [
        len(a.notes["redteamer_conversation"].turns)
        for a in result
        if "redteamer_conversation" in a.notes
    ]
    assert len(rt_conv_lengths) > 0
    assert max(rt_conv_lengths) > min(
        rt_conv_lengths
    ), "redteamer conversation should grow across turns"


def test_toxconv_linear_thread_count():
    """linear mode should produce exactly ``generations`` conversation threads."""
    _config.load_base_config()
    generations = 3
    _config.run.generations = generations
    p = _plugins.load_plugin(
        "probes.atkgen.ToxConv",
        config_root=_make_toxconv_config(branching="linear"),
    )
    p.max_calls_per_conv = 1
    g = _plugins.load_plugin("generators.test.Lipsum", config_root=garak._config)
    with patch.object(p, "_should_terminate_conversation", side_effect=_no_early_stop):
        with tempfile.NamedTemporaryFile(
            mode="w+", encoding="utf-8"
        ) as temp_report_file:
            _config.transient.reportfile = temp_report_file
            _config.transient.report_filename = temp_report_file.name
            result = p.probe(g)

    assert (
        len(result) == generations
    ), "linear mode should produce one attempt per generation (thread)"


def test_toxconv_linear_no_branching():
    """In linear mode, each attempt should have exactly one conversation branch."""
    _config.load_base_config()
    _config.run.generations = 3
    p = _plugins.load_plugin(
        "probes.atkgen.ToxConv",
        config_root=_make_toxconv_config(branching="linear"),
    )
    p.max_calls_per_conv = 2
    g = _plugins.load_plugin("generators.test.Lipsum", config_root=garak._config)
    with patch.object(p, "_should_terminate_conversation", side_effect=_no_early_stop):
        with tempfile.NamedTemporaryFile(
            mode="w+", encoding="utf-8"
        ) as temp_report_file:
            _config.transient.reportfile = temp_report_file
            _config.transient.report_filename = temp_report_file.name
            result = p.probe(g)

    for attempt in result:
        assert (
            len(attempt.conversations) == 1
        ), "linear mode must not branch: each attempt should have exactly one conversation"


def test_toxconv_branchy_expands():
    """branchy mode should produce more attempts than seeds after multiple turns."""
    _config.load_base_config()
    _config.run.generations = 2
    p = _plugins.load_plugin(
        "probes.atkgen.ToxConv",
        config_root=_make_toxconv_config(branching="branchy", convs_per_generation=1),
    )
    p.max_calls_per_conv = 2
    g = _plugins.load_plugin("generators.test.Lipsum", config_root=garak._config)
    with patch.object(p, "_should_terminate_conversation", side_effect=_no_early_stop):
        with tempfile.NamedTemporaryFile(
            mode="w+", encoding="utf-8"
        ) as temp_report_file:
            _config.transient.reportfile = temp_report_file
            _config.transient.report_filename = temp_report_file.name
            result = p.probe(g)

    # With 1 seed, generations=2, and 2 turns: turn 0 → 1 attempt (2 branches),
    # turn 1 → 2 next attempts. Total > 1 seed.
    assert (
        len(result) > 1
    ), "branchy mode should produce more attempts than the initial seed count"


@pytest.mark.parametrize("branching", ["linear", "branchy"])
def test_toxconv_early_stop_on_hit(branching):
    """Branches where the detector fires should not generate a next-turn attempt."""
    _config.load_base_config()
    _config.run.generations = 2
    p = _plugins.load_plugin(
        "probes.atkgen.ToxConv",
        config_root=_make_toxconv_config(branching=branching, convs_per_generation=1),
    )
    p.max_calls_per_conv = 3
    g = _plugins.load_plugin("generators.test.Lipsum", config_root=garak._config)

    # Stub the detector to always signal a hit on every output
    with patch.object(
        p,
        "_should_terminate_conversation",
        return_value=[True, True],
    ):
        with tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8") as f:
            _config.transient.reportfile = f
            _config.transient.report_filename = f.name
            result = p.probe(g)

    # Only turn-0 attempts should exist; early stopping prevents turn-1 attempts
    assert all(
        len(a.conversations[0].turns) <= 2 for a in result
    ), "no turn-1 attempts should be generated when the detector fires on turn 0"


def test_toxconv_branchy_respects_inference_cap():
    """branchy mode stops queuing next turns once soft_probe_prompt_cap * generations responses are collected."""
    _config.load_base_config()
    generations = 2
    # cap = 1 * 2 = 2 inferences; fires as soon as the single init attempt
    # completes (it produces exactly 2 outputs), so no turn-1 attempts are queued.
    _config.run.generations = generations
    _config.run.soft_probe_prompt_cap = 1
    p = _plugins.load_plugin(
        "probes.atkgen.ToxConv",
        config_root=_make_toxconv_config(branching="branchy", convs_per_generation=1),
    )
    p.max_calls_per_conv = 5  # well above where the cap should fire
    g = _plugins.load_plugin("generators.test.Lipsum", config_root=garak._config)
    with patch.object(p, "_should_terminate_conversation", side_effect=_no_early_stop):
        with tempfile.NamedTemporaryFile(
            mode="w+", encoding="utf-8"
        ) as temp_report_file:
            _config.transient.reportfile = temp_report_file
            _config.transient.report_filename = temp_report_file.name
            result = p.probe(g)

    # Only the init attempt should exist; cap fires in _generate_next_attempts
    # before any turn-1 attempt is queued.
    assert (
        len(result) == 1
    ), "branchy inference cap should stop expansion after the init attempt"
    # The init attempt's first conversation should have exactly 2 turns (user + assistant)
    assert len(result[0].conversations[0].turns) == 2


def test_toxconv_branchy_deduplicates_responses():
    """branchy mode must not branch on duplicate target responses."""
    _config.load_base_config()
    _config.run.generations = 3  # three identical responses from test.Repeat
    p = _plugins.load_plugin(
        "probes.atkgen.ToxConv",
        config_root=_make_toxconv_config(branching="branchy", convs_per_generation=1),
    )
    p.max_calls_per_conv = 2
    # test.Repeat echoes the prompt identically for every generation
    g = _plugins.load_plugin("generators.test.Repeat", config_root=garak._config)
    with patch.object(p, "_should_terminate_conversation", side_effect=_no_early_stop):
        with tempfile.NamedTemporaryFile(
            mode="w+", encoding="utf-8"
        ) as temp_report_file:
            _config.transient.reportfile = temp_report_file
            _config.transient.report_filename = temp_report_file.name
            result = p.probe(g)

    # All 3 branches produce the same response text, so only 1 next attempt
    # should be generated at turn 1; total attempts = 1 (turn 0) + 1 (turn 1).
    assert (
        len(result) == 2
    ), "branchy mode should collapse identical responses to a single branch"
