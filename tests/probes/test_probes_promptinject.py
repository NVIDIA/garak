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
