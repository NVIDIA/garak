import pytest

import garak._plugins
import garak.attempt

PROMPTINJECT_PROBES = (
    "probes.promptinject.HijackHateHumans",
    "probes.promptinject.HijackKillHumans",
    "probes.promptinject.HijackLongPrompt",
)


@pytest.mark.parametrize("probename", PROMPTINJECT_PROBES)
def test_promptinject_settings_match_prompt(probename):
    p = garak._plugins.load_plugin(probename)
    # the same prompt text can appear with several configs, so allow any of them
    settings_by_prompt = {}
    for pi in p.pi_prompts:
        settings_by_prompt.setdefault(pi["prompt"], []).append(pi["settings"])
    for seq, prompt in enumerate(p.prompts):
        attempt = garak.attempt.Attempt(prompt=garak.attempt.Message(prompt))
        attempt = p._attempt_prestore_hook(attempt, seq)
        assert (
            attempt.notes["settings"] in settings_by_prompt[prompt]
        ), f"settings attached to prompt {seq} belong to a different prompt"


@pytest.mark.parametrize("probename", PROMPTINJECT_PROBES)
def test_promptinject_generator_options_restored(probename):
    import random
    import tempfile
    from garak import _config

    _config.load_base_config()

    test_generation_limit = random.randint(1024, 4096)
    g = garak._plugins.load_plugin("generators.test.Blank")
    g.max_tokens = test_generation_limit
    p = garak._plugins.load_plugin(probename)

    with tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8") as temp_report_file:
        _config.transient.reportfile = temp_report_file
        _config.transient.report_filename = temp_report_file.name
        result = p.probe(g)

    assert (
        g.max_tokens == test_generation_limit
    ), "The generator configuration should be restored after probing"
