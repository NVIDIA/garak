import pytest

from garak.resources import fixer

EMPTY_CONFIG = {"system": {"lite": False}}
BASE_TEST_CONFIG = {"plugins": {"probe_spec": "test.Test"}}


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
    assert revised_config["plugins"] == post_migration_dict
    if migration_name is None:
        assert (
            not mock_log_info.called
        ), "Logging should not be called when no migrations are applied"
    else:
        # expect `migration_name` in a log call via mock of logging.info()
        assert "Migration performed" in mock_log_info.call_args.args[0]
        found_class = False
        for calls in mock_log_info.call_args_list:
            found_class = migration_name in calls.args[0]
            if found_class:
                break
        assert found_class
