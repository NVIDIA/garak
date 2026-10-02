import pytest

from garak.resources import fixer
from garak.resources.fixer import _plugin

EMPTY_CONFIG = {"system": {"lite": False}}
BASE_TEST_CONFIG = {"plugins": {"probe_spec": "test.Test"}}
OLD_SYSPROMPT_PROBE = "probes.sysprompt_extraction.SystemPromptExtraction"
NEW_SYSPROMPT_PROBES = (
    "probes.sysprompt_extraction.DirectRequests",
    "probes.sysprompt_extraction.RolePlayingClaimAuthority",
    "probes.sysprompt_extraction.WorldBuildingScenarios",
    "probes.sysprompt_extraction.RolePlayingTargetPersona",
    "probes.sysprompt_extraction.EncodingBasedAttacks",
    "probes.sysprompt_extraction.IgnorePreviousInstructions",
    "probes.sysprompt_extraction.PerspectiveShifting",
    "probes.sysprompt_extraction.Programming",
    "probes.sysprompt_extraction.GiveExamples",
    "probes.sysprompt_extraction.StrongArmScenarios",
    "probes.sysprompt_extraction.StrongArmClaimAuthority",
)


def test_fixer_empty(mocker):
    import logging

    mock_log_info = mocker.patch.object(
        logging,
        "info",
    )
    fixer.migrate(EMPTY_CONFIG)
    assert (
        not mock_log_info.called
    ), "Logging should not be when config contains no modifiable data"


@pytest.mark.parametrize(
    "migration_name, pre_migration_dict, post_migration_dict",
    [
        (
            None,
            {},
            {"probe_spec": "test.Test"},
        ),
        (
            "RenameGCG",
            {
                "probe_spec": "lmrc,gcg,tap",
            },
            {
                "probe_spec": "lmrc,suffix,tap",
            },
        ),
        (
            "RenameGCG",
            {
                "probe_spec": "lmrc,gcg,tap",
                "probes": {"gcg": {"GOAL": "fake the goal"}},
            },
            {
                "probe_spec": "lmrc,suffix,tap",
                "probes": {"suffix": {"GOAL": "fake the goal"}},
            },
        ),
        (
            "RenameGCG",
            {
                "probe_spec": "lmrc,gcg.GCGCached,tap",
                "probes": {
                    "gcg": {
                        "GCGCached": {},
                        "GOAL": "fake the goal",
                    }
                },
            },
            {
                "probe_spec": "lmrc,suffix.GCGCached,tap",
                "probes": {
                    "suffix": {
                        "GCGCached": {},
                        "GOAL": "fake the goal",
                    }
                },
            },
        ),
        (
            "RenameContinuation",
            {
                "probe_spec": "lmrc,continuation.ContinueSlursReclaimedSlurs80,tap",
            },
            {
                "probe_spec": "lmrc,continuation.ContinueSlursReclaimedSlurs,tap",
            },
        ),
        (
            "RenameContinuation",
            {
                "probe_spec": "lmrc,continuation,tap",
                "probes": {
                    "continuation": {
                        "ContinueSlursReclaimedSlurs80": {
                            "source_resource_filename": "fake_data_file.json"
                        }
                    }
                },
            },
            {
                "probe_spec": "lmrc,continuation,tap",
                "probes": {
                    "continuation": {
                        "ContinueSlursReclaimedSlurs": {
                            "source_resource_filename": "fake_data_file.json"
                        }
                    }
                },
            },
        ),
        (
            "RenameKnownbadsignatures",
            {
                "probe_spec": "knownbadsignatures.EICAR,lmrc,tap",
            },
            {
                "probe_spec": "av_spam_scanning.EICAR,lmrc,tap",
            },
        ),
        (
            "RenameKnownbadsignatures",
            {
                "probe_spec": "knownbadsignatures,lmrc,tap",
            },
            {
                "probe_spec": "av_spam_scanning,lmrc,tap",
            },
        ),
        (
            "RenameReplay",
            {
                "probe_spec": "lmrc,tap,replay",
            },
            {
                "probe_spec": "lmrc,tap,divergence",
            },
        ),
        (
            "RenameReplay",
            {
                "probe_spec": "lmrc,tap,replay.Repeat",
            },
            {
                "probe_spec": "lmrc,tap,divergence.Repeat",
            },
        ),
        (
            "RenameDanInTheWild",
            {
                "probe_spec": "dan.DanInTheWildMini,dan.DanInTheWild",
            },
            {
                "probe_spec": "dan.DanInTheWild,dan.DanInTheWildFull",
            },
        ),
        (
            "RenameXSS",
            {
                "probe_spec": "lmrc,xss.MdExfil20230929",
            },
            {
                "probe_spec": "lmrc,web_injection.PlaygroundMarkdownExfil",
            },
        ),
        (
            "RenameXSS",
            {
                "probe_spec": "test.Test",
                "detector_spec": "xss.MarkdownExfil20230929",
            },
            {
                "probe_spec": "test.Test",
                "detector_spec": "web_injection.PlaygroundMarkdownExfil",
            },
        ),
        (
            "SplitSystemPromptExtraction",
            {
                "probe_spec": "sysprompt_extraction.SystemPromptExtraction",
            },
            {
                "probe_spec": ",".join(
                    probe.removeprefix("probes.") for probe in NEW_SYSPROMPT_PROBES
                ),
            },
        ),
    ],
)
def test_fixer_migrate(
    mocker,
    migration_name,
    pre_migration_dict,
    post_migration_dict,
):
    import logging
    import copy

    mock_log_info = mocker.patch.object(
        logging,
        "info",
    )
    config_dict = copy.deepcopy(BASE_TEST_CONFIG)
    config_dict["plugins"] = config_dict["plugins"] | pre_migration_dict
    revised_config = fixer.migrate(config_dict)

    # probe_spec/buff_spec are folded into run.spec and removed from plugins;
    # any other (possibly renamed) plugin keys are retained as-is
    expected_plugins = {
        k: v
        for k, v in post_migration_dict.items()
        if k not in ("probe_spec", "buff_spec")
    }
    assert (
        revised_config.get("plugins", {}) == expected_plugins
    ), "non-selection plugin keys keep their renamed values; probe_spec/buff_spec move to run.spec"

    probe_spec_val = post_migration_dict.get("probe_spec")
    expected_include = [
        f"probes.{clause.strip()}"
        for clause in (probe_spec_val or "").split(",")
        if clause.strip()
    ]
    assert revised_config.get("run", {}).get("spec") == {
        "include": expected_include,
    }, "the (renamed) selection must be converted into run.spec (empty exclude suppressed)"

    if migration_name is not None:
        # expect `migration_name` in a log call via mock of logging.info()
        found_class = any(
            migration_name in call.args[0] for call in mock_log_info.call_args_list
        )
        assert found_class, f"expected migration {migration_name} to be logged"


def test_fixer_sysprompt_migration_expands_modern_config():
    config = {
        "run": {
            "spec": {
                "include": [
                    OLD_SYSPROMPT_PROBE,
                    {"tag": "quality:Security"},
                ],
                "exclude": [OLD_SYSPROMPT_PROBE],
            }
        },
        "plugins": {
            "probes": {
                "sysprompt_extraction": {
                    "SystemPromptExtraction": {
                        "system_prompt_subsample": 7,
                        "follow_prompt_cap": False,
                    }
                }
            }
        },
    }

    revised = fixer.migrate(config)

    assert revised["run"]["spec"] == {
        "include": [*NEW_SYSPROMPT_PROBES, {"tag": "quality:Security"}],
        "exclude": list(NEW_SYSPROMPT_PROBES),
    }, "both selection polarities must expand to every replacement probe"
    assert (
        revised["plugins"] == config["plugins"]
    ), "the run.spec migration must not alter plugin configuration"


def test_fixer_rename_v2_rewrites_run_spec_only():
    config = {
        "run": {
            "spec": {
                "include": ["probes.legacy.Old", {"tag": "demon"}],
                "exclude": ["probes.legacy.Old", "probes.legacy.OldSuffix"],
            }
        },
        "plugins": {"probes": {"legacy": {"Old": {"value": 1}}}},
    }

    revised = _plugin.rename_v2(
        config,
        "probes.legacy.Old",
        "probes.modern.New",
    )

    assert revised["run"]["spec"] == {
        "include": ["probes.modern.New", {"tag": "demon"}],
        "exclude": ["probes.modern.New", "probes.legacy.OldSuffix"],
    }, "rename_v2 must replace exact selectors in both polarities"
    assert (
        revised["plugins"] == config["plugins"]
    ), "rename_v2 must not alter plugin configuration"
    assert (
        config["run"]["spec"]["include"][0] == "probes.legacy.Old"
    ), "rename_v2 must not mutate its input"


# The legacy -> run.spec mapping itself is covered by tests/test_spec.py
# (legacy_selection_spec); these cases exercise only the fixer wrapper behavior:
# key removal, "user-set run.spec wins", and the no-op case. Compose-with-rename
# is already covered by the run.spec assertions in test_fixer_migrate above.
@pytest.mark.parametrize(
    "pre, post",
    [
        (
            {
                "plugins": {"probe_spec": "dan", "buff_spec": "lowercase"},
                "run": {"probe_tags": "owasp:llm01"},
            },
            {
                "run": {
                    "spec": {
                        "include": [
                            "probes.dan",
                            "buffs.lowercase",
                            {"tag": "owasp:llm01"},
                        ],
                    }
                },
            },
        ),
        (
            {
                "plugins": {"probe_spec": "dan"},
                "run": {"spec": {"include": ["probes.lmrc"], "exclude": []}},
            },
            {
                "run": {"spec": {"include": ["probes.lmrc"], "exclude": []}},
            },
        ),
        (
            {"plugins": {"target_type": "test.Blank"}},
            {"plugins": {"target_type": "test.Blank"}},
        ),
    ],
)
def test_fixer_run_spec_apply(pre, post):
    import copy
    import importlib

    # date-prefixed module names are not valid import identifiers
    mod = importlib.import_module("garak.resources.fixer.20260612_run_spec")
    MapLegacySelectionToSpec = mod.MapLegacySelectionToSpec

    revised = MapLegacySelectionToSpec.apply(copy.deepcopy(pre))
    assert revised == post, (
        "fixer must fold legacy selection keys into run.spec, drop emptied "
        "containers/keys, and leave an explicit run.spec (or selection-free config) untouched"
    )


def test_fixer_run_spec_rejects_prefixed_legacy_value():
    import copy
    import importlib

    mod = importlib.import_module("garak.resources.fixer.20260612_run_spec")
    with pytest.raises(ValueError, match="cannot be migrated"):
        mod.MapLegacySelectionToSpec.apply(
            copy.deepcopy({"plugins": {"buff_spec": "buffs.encoding.CharCode"}})
        )


def test_fixer_run_spec_rejects_unknown_migrated_plugin():
    # an invalid prefix (e.g. 's.encoding.CharCode') migrates syntactically but
    # names no real plugin; --fix must not emit a config that fails at run time
    import copy

    with pytest.raises(ValueError, match="unknown plugins"):
        fixer.migrate(copy.deepcopy({"plugins": {"buff_spec": "s.encoding.CharCode"}}))


def test_fixer_run_spec_drops_ignored_invalid_legacy_value():
    # an explicit run.spec wins; deprecated keys are dropped without validation,
    # matching runtime config-load (an ignored bad value must not block migration)
    import copy
    import importlib

    mod = importlib.import_module("garak.resources.fixer.20260612_run_spec")
    revised = mod.MapLegacySelectionToSpec.apply(
        copy.deepcopy(
            {
                "plugins": {"buff_spec": "buffs.encoding.CharCode"},
                "run": {"spec": {"include": ["probes.dan"]}},
            }
        )
    )
    assert revised == {
        "run": {"spec": {"include": ["probes.dan"]}}
    }, "ignored deprecated key must be dropped, explicit run.spec untouched, no error"


def test_fixer_does_not_validate_unchanged_explicit_run_spec():
    revised = fixer.migrate(
        {
            "plugins": {"buff_spec": "buffs.encoding.CharCode"},
            "run": {"spec": {"include": ["probes.unknown.Missing"]}},
        }
    )

    assert revised == {
        "run": {"spec": {"include": ["probes.unknown.Missing"]}}
    }, "an explicit run.spec untouched by migrations must retain existing behavior"


def test_fixer_modules_have_date_prefix():
    import re
    from pathlib import Path

    fixer_dir = Path(fixer.__file__).parent
    date_prefix = re.compile(r"^\d{8}_")
    offenders = [
        path.name
        for path in fixer_dir.glob("*.py")
        if not path.name.startswith("_") and not date_prefix.match(path.name)
    ]
    assert not offenders, (
        "migration modules must be named 'YYYYMMDD_<desc>.py' so they apply in "
        f"chronological order; offenders: {offenders}"
    )
