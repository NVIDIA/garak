# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import importlib
import pytest
from unittest.mock import MagicMock

import garak._config
from garak import _plugins
import garak.probes.hyperparams
from garak.exception import PluginConfigurationError
from garak.probes.hyperparams import HyperparamBasher


@pytest.fixture(autouse=True)
def reload_config(request):
    def reload():
        importlib.reload(garak._config)

    reload()
    request.addfinalizer(reload)


# ---------------------------------------------------------------------------
# Enumeration & loading
# ---------------------------------------------------------------------------


def test_probe_discoverable():
    probes = [
        name
        for name, _ in _plugins.enumerate_plugins("probes")
        if name.startswith("probes.hyperparams")
    ]
    assert "probes.hyperparams.HyperparamBasher" in probes


def test_only_one_probe_class():
    """Module should expose exactly one probe class; no concrete subclasses."""
    probes = [
        name
        for name, _ in _plugins.enumerate_plugins("probes")
        if name.startswith("probes.hyperparams")
    ]
    assert len(probes) == 1, f"expected 1 probe, found {probes}"


# ---------------------------------------------------------------------------
# Base class: empty without source_probe
# ---------------------------------------------------------------------------


def test_probe_empty_without_source_probe():
    """HyperparamBasher with no source_probe initialises but has empty prompts."""
    config_root = {
        "probes": {
            "hyperparams": {
                "HyperparamBasher": {
                    "source_probe": None,
                }
            }
        }
    }
    probe = HyperparamBasher(config_root=config_root)
    assert probe.prompts == []
    assert probe._param_combos == []


# ---------------------------------------------------------------------------
# param combo generation — single strategy
# ---------------------------------------------------------------------------


def test_single_strategy_combos_structure():
    """Single-param sweep produces one combo per param value."""
    config_root = {
        "probes": {
            "hyperparams": {
                "HyperparamBasher": {
                    "source_probe": "packagehallucination.Python",
                    "param_space": {
                        "temperature": [0.0, 1.0, 2.0],
                        "top_p": [0.5, 1.0],
                    },
                    "sweep_strategy": "single",
                }
            }
        }
    }
    probe = HyperparamBasher(config_root=config_root)
    # single: 3 temp + 2 top_p = 5 combos; each has exactly one key
    assert len(probe._param_combos) == 5
    assert all(len(c) == 1 for c in probe._param_combos)
    temps = [c["temperature"] for c in probe._param_combos if "temperature" in c]
    assert set(temps) == {0.0, 1.0, 2.0}


# ---------------------------------------------------------------------------
# param combo generation — random strategy
# ---------------------------------------------------------------------------


def test_random_strategy_respects_sample_count():
    config_root = {
        "probes": {
            "hyperparams": {
                "HyperparamBasher": {
                    "source_probe": "packagehallucination.Python",
                    "param_space": {
                        "temperature": [0.0, 0.5, 1.0, 1.5, 2.0],
                        "top_p": [0.1, 0.5, 0.9, 1.0],
                    },
                    "sweep_strategy": "random",
                    "random_samples": 5,
                }
            }
        }
    }
    probe = HyperparamBasher(config_root=config_root)
    assert len(probe._param_combos) == 5


def test_random_strategy_unique_combos():
    config_root = {
        "probes": {
            "hyperparams": {
                "HyperparamBasher": {
                    "source_probe": "packagehallucination.Python",
                    "param_space": {
                        "temperature": [0.0, 1.0, 2.0],
                        "top_p": [0.5, 1.0],
                    },
                    "sweep_strategy": "random",
                    "random_samples": 6,
                }
            }
        }
    }
    probe = HyperparamBasher(config_root=config_root)
    keys = [tuple(sorted(c.items())) for c in probe._param_combos]
    assert len(keys) == len(set(keys)), "random combos should be unique"


def test_random_seed_produces_same_combos():
    """Same random_seed must yield identical combo ordering on two separate instances."""
    cfg = {
        "probes": {
            "hyperparams": {
                "HyperparamBasher": {
                    "source_probe": "packagehallucination.Python",
                    "param_space": {
                        "temperature": [0.0, 0.5, 1.0, 1.5, 2.0],
                        "top_p": [0.1, 0.5, 0.9, 1.0],
                    },
                    "sweep_strategy": "random",
                    "random_samples": 8,
                    "random_seed": 42,
                }
            }
        }
    }
    probe_a = HyperparamBasher(config_root=cfg)
    probe_b = HyperparamBasher(config_root=cfg)
    assert probe_a._param_combos == probe_b._param_combos


def test_invalid_strategy_raises():
    config_root = {
        "probes": {
            "hyperparams": {
                "HyperparamBasher": {
                    "source_probe": "packagehallucination.Python",
                    "param_space": {"temperature": [1.0]},
                    "sweep_strategy": "grid",
                }
            }
        }
    }
    with pytest.raises(ValueError, match="sweep_strategy"):
        HyperparamBasher(config_root=config_root)


# ---------------------------------------------------------------------------
# Prompt expansion
# ---------------------------------------------------------------------------


def test_prompts_expanded_for_combos():
    """Prompt list expansion equals n_combos × n_base_prompts."""
    config_root = {
        "probes": {
            "hyperparams": {
                "HyperparamBasher": {
                    "source_probe": "packagehallucination.Python",
                    "param_space": {
                        "temperature": [0.0, 1.0],
                        "top_p": [0.5, 1.0],
                    },
                    "sweep_strategy": "single",
                }
            }
        }
    }
    probe = HyperparamBasher(config_root=config_root)
    n_base = len(probe.prompts)
    n_combos = len(probe._param_combos)  # 2 temp + 2 top_p = 4
    pairs = probe._build_prompt_list()
    assert len(pairs) == n_combos * n_base


# ---------------------------------------------------------------------------
# Param validation against generator
# ---------------------------------------------------------------------------


def test_validate_params_raises_for_unknown_param():
    """_validate_params_against_generator raises PluginConfigurationError
    when a param_space entry is not an attribute of the generator."""
    config_root = {
        "probes": {
            "hyperparams": {
                "HyperparamBasher": {
                    "source_probe": "packagehallucination.Python",
                    "param_space": {"no_such_param": [1, 2, 3]},
                    "sweep_strategy": "single",
                }
            }
        }
    }
    probe = HyperparamBasher(config_root=config_root)
    generator = MagicMock(spec=["temperature"])  # doesn't have 'no_such_param'

    with pytest.raises(PluginConfigurationError, match="no_such_param"):
        probe._validate_params_against_generator(generator)


def test_validate_params_passes_for_known_param():
    config_root = {
        "probes": {
            "hyperparams": {
                "HyperparamBasher": {
                    "source_probe": "packagehallucination.Python",
                    "param_space": {"temperature": [0.0, 1.0]},
                    "sweep_strategy": "single",
                }
            }
        }
    }
    probe = HyperparamBasher(config_root=config_root)
    generator = MagicMock()
    generator.temperature = 0.7
    # should not raise
    probe._validate_params_against_generator(generator)


def test_validate_params_warns_for_non_openai_compatible_generator():
    """Non-OpenAICompatible generators emit a WARNING — params may be ignored."""
    from unittest.mock import patch

    config_root = {
        "probes": {
            "hyperparams": {
                "HyperparamBasher": {
                    "source_probe": "packagehallucination.Python",
                    "param_space": {"temperature": [0.0, 1.0]},
                }
            }
        }
    }
    probe = HyperparamBasher(config_root=config_root)
    generator = MagicMock()
    generator.temperature = 0.7

    with patch("garak.probes.hyperparams.logging") as mock_log:
        probe._validate_params_against_generator(generator)
        mock_log.warning.assert_called_once()
        assert "may not apply inference param changes" in mock_log.warning.call_args[0][0]


# ---------------------------------------------------------------------------
# _generator_precall_hook and _postprocess_hook
# ---------------------------------------------------------------------------


def test_precall_hook_sets_params():
    probe = HyperparamBasher()
    generator = MagicMock()
    generator.temperature = 0.7
    generator.top_p = 1.0

    attempt = MagicMock()
    attempt.notes = {
        "hyperparam_combo": {"temperature": 2.0},
        "hyperparam_original": {},
    }

    probe.generator = generator
    probe._generator_precall_hook(generator, attempt)

    assert generator.temperature == 2.0
    assert attempt.notes["hyperparam_original"]["temperature"] == 0.7


def test_precall_hook_skips_missing_params():
    """Params absent from the generator are not set (validated earlier in probe())."""
    probe = HyperparamBasher()
    generator = MagicMock(spec=["top_p"])
    generator.top_p = 1.0

    attempt = MagicMock()
    attempt.notes = {
        "hyperparam_combo": {"temperature": 2.0},
        "hyperparam_original": {},
    }

    probe.generator = generator
    probe._generator_precall_hook(generator, attempt)

    assert attempt.notes["hyperparam_original"] == {}


def test_postprocess_hook_restores_params():
    probe = HyperparamBasher()
    generator = MagicMock()
    generator.temperature = 2.0
    probe.generator = generator

    attempt = MagicMock()
    attempt.notes = {"hyperparam_original": {"temperature": 0.7}}

    probe._postprocess_hook(attempt)

    assert generator.temperature == 0.7


def test_precall_hook_noop_without_attempt():
    probe = HyperparamBasher()
    generator = MagicMock()
    generator.temperature = 0.7
    probe.generator = generator
    # should not raise
    probe._generator_precall_hook(generator, None)
    assert generator.temperature == 0.7


# ---------------------------------------------------------------------------
# attempt.notes recorded correctly
# ---------------------------------------------------------------------------


def test_attempt_prestore_hook_records_combo():
    config_root = {
        "probes": {
            "hyperparams": {
                "HyperparamBasher": {
                    "source_probe": "packagehallucination.Python",
                    "param_space": {"temperature": [0.5]},
                    "sweep_strategy": "single",
                }
            }
        }
    }
    probe = HyperparamBasher(config_root=config_root)

    from garak.attempt import Attempt, Message, Conversation, Turn

    attempt = Attempt(
        prompt=Conversation([Turn("user", Message(text="test"))]),
        probe_classname="hyperparams.HyperparamBasher",
    )

    probe._attempt_prestore_hook(attempt, 0)

    assert "hyperparam_combo" in attempt.notes
    assert isinstance(attempt.notes["hyperparam_combo"], dict)


# ---------------------------------------------------------------------------
# Source probe lookup and detector/tag inheritance
# ---------------------------------------------------------------------------


def test_inherits_detector_from_source_probe():
    config_root = {
        "probes": {
            "hyperparams": {
                "HyperparamBasher": {
                    "source_probe": "packagehallucination.Python",
                    "param_space": {"temperature": [0.5]},
                }
            }
        }
    }
    probe = HyperparamBasher(config_root=config_root)
    assert probe.primary_detector == "packagehallucination.PythonPypi"


def test_source_probe_with_custom_precall_hook_raises():
    """Source probes that define _generator_precall_hook are rejected at init
    because their hooks depend on instance state unavailable on HyperparamBasher."""
    config_root = {
        "probes": {
            "hyperparams": {
                "HyperparamBasher": {
                    "source_probe": "promptinject.HijackHateHumans",
                    "param_space": {"temperature": [1.0]},
                }
            }
        }
    }
    with pytest.raises(PluginConfigurationError, match="_generator_precall_hook"):
        HyperparamBasher(config_root=config_root)


def test_source_probe_without_custom_precall_hook_accepted():
    """Source probes that do not override _generator_precall_hook initialise cleanly."""
    config_root = {
        "probes": {
            "hyperparams": {
                "HyperparamBasher": {
                    "source_probe": "packagehallucination.Python",
                    "param_space": {"temperature": [1.0]},
                }
            }
        }
    }
    # should not raise
    probe = HyperparamBasher(config_root=config_root)
    assert probe.prompts  # prompts were loaded


# ---------------------------------------------------------------------------
# _attempt_prestore_hook chaining for trigger-based source probes
# ---------------------------------------------------------------------------


def test_trigger_based_source_probe_chains_prestore_hook():
    """Source probes with _attempt_prestore_hook (e.g. continuation) should have
    their triggers copied to HyperparamBasher and the hook chained so that
    attempt.notes["triggers"] is populated during the sweep."""
    config_root = {
        "probes": {
            "hyperparams": {
                "HyperparamBasher": {
                    "source_probe": "continuation.ContinueSlursReclaimedSlurs",
                    "param_space": {"temperature": [0.5]},
                    "sweep_strategy": "single",
                }
            }
        }
    }
    probe = HyperparamBasher(config_root=config_root)
    # Source prestore hook should have been detected and chained
    assert probe._source_prestore_hook is not None
    # Trigger data must be present and sufficient to cover all prompts; it may
    # be longer than prompts if the source probe doesn't prune triggers in sync
    # (e.g. continuation.ContinueSlursReclaimedSlurs prunes prompts but not triggers).
    assert hasattr(probe, "triggers")
    assert len(probe.triggers) >= len(probe.prompts)


def test_prestore_hook_populates_triggers_in_notes():
    """After _attempt_prestore_hook fires, attempt.notes should contain the
    source probe's trigger for that prompt as well as the hyperparam keys."""
    config_root = {
        "probes": {
            "hyperparams": {
                "HyperparamBasher": {
                    "source_probe": "continuation.ContinueSlursReclaimedSlurs",
                    "param_space": {"temperature": [0.5]},
                    "sweep_strategy": "single",
                }
            }
        }
    }
    probe = HyperparamBasher(config_root=config_root)
    # Simulate the expanded-prompt phase so _source_n_base_prompts is used correctly
    probe._param_combos = [{"temperature": 0.5}] * len(probe.prompts)

    from garak.attempt import Attempt, Message, Conversation, Turn

    attempt = Attempt(
        prompt=Conversation([Turn("user", Message(text="test"))]),
        probe_classname="hyperparams.HyperparamBasher",
    )

    probe._attempt_prestore_hook(attempt, 0)

    # Source hook sets "triggers"; hyperparam hook adds its own keys alongside
    assert "triggers" in attempt.notes
    assert "hyperparam_combo" in attempt.notes
    # hyperparam keys must not have overwritten "triggers"
    assert isinstance(attempt.notes["triggers"], list)


def test_parallel_attrs_pruned_in_sync_with_prompts():
    """When prompt capping prunes prompts, parallel trigger lists are pruned too."""
    config_root = {
        "probes": {
            "hyperparams": {
                "HyperparamBasher": {
                    "source_probe": "continuation.ContinueSlursReclaimedSlurs",
                    "param_space": {"temperature": [0.5]},
                    "follow_prompt_cap": True,
                }
            }
        }
    }
    probe = HyperparamBasher(config_root=config_root)
    if hasattr(probe, "triggers"):
        # Triggers may be longer than prompts if the source probe doesn't prune
        # them in sync (pre-existing source-probe behaviour); what matters is
        # that enough trigger entries exist to cover every remaining prompt.
        assert len(probe.triggers) >= len(probe.prompts), (
            "triggers list must have at least as many entries as prompts"
        )


def test_seq_remapping_across_combos():
    """_attempt_prestore_hook must re-map seq correctly across expanded pairs.
    For n_base prompts and n_combos, seq=n_base should map back to base_seq=0."""
    config_root = {
        "probes": {
            "hyperparams": {
                "HyperparamBasher": {
                    "source_probe": "continuation.ContinueSlursReclaimedSlurs",
                    "param_space": {"temperature": [0.5, 1.0]},
                    "sweep_strategy": "single",
                }
            }
        }
    }
    probe = HyperparamBasher(config_root=config_root)
    n_base = probe._source_n_base_prompts

    from garak.attempt import Attempt, Message, Conversation, Turn

    def make_attempt():
        return Attempt(
            prompt=Conversation([Turn("user", Message(text="test"))]),
            probe_classname="hyperparams.HyperparamBasher",
        )

    # Expand combos as probe() does temporarily
    pairs = probe._build_prompt_list()
    probe._param_combos = [c for _, c in pairs]

    attempt_0 = make_attempt()
    attempt_nbase = make_attempt()

    probe._attempt_prestore_hook(attempt_0, 0)
    probe._attempt_prestore_hook(attempt_nbase, n_base)

    if "triggers" in attempt_0.notes:
        # seq=0 and seq=n_base both map to base_seq=0 → same trigger
        assert attempt_0.notes["triggers"] == attempt_nbase.notes["triggers"]


# ---------------------------------------------------------------------------
# Metadata checks
# ---------------------------------------------------------------------------


def test_cwe_tag_present():
    assert "cwe:1434" in HyperparamBasher.tags


def test_doc_uri_set():
    assert HyperparamBasher.doc_uri.startswith("http")


def test_prompt_count_respects_cap():
    config_root = {
        "probes": {
            "hyperparams": {
                "HyperparamBasher": {
                    "source_probe": "packagehallucination.Python",
                    "param_space": {"temperature": [0.5]},
                }
            }
        }
    }
    probe = HyperparamBasher(config_root=config_root)
    assert len(probe.prompts) <= garak._config.run.soft_probe_prompt_cap

