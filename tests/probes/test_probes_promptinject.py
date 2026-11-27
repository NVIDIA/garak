import os

import pytest

import garak._plugins
import garak.attempt
from garak import _config

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


@pytest.mark.parametrize(
    "probename",
    PROMPTINJECT_PROBES + tuple(f"{name}Full" for name in PROMPTINJECT_PROBES),
)
def test_promptinject_prompts_are_unique(probename):
    p = garak._plugins.load_plugin(probename)
    assert len(set(p.prompts)) == len(
        p.prompts
    ), "a prompt should be built once; repeats are what generations is for"


ORIGINAL_GENERATION_PARAMS = {
    "temperature": 0.123,
    "top_p": 0.456,
    "frequency_penalty": 0.0,
    "presence_penalty": 0.0,
    "max_tokens": 4096,
}


def _recording_generator():
    """a test.Repeat generator exposing all five PromptInject settings, which
    records the settings it was called with"""
    g = garak._plugins.load_plugin("generators.test.Repeat", config_root=_config)
    for attrib, value in ORIGINAL_GENERATION_PARAMS.items():
        setattr(g, attrib, value)
    g.calls = []
    call_model = g._call_model

    def _call_model(prompt, generations_this_call=1):
        g.calls.append({a: getattr(g, a) for a in ORIGINAL_GENERATION_PARAMS})
        return call_model(prompt, generations_this_call)

    g._call_model = _call_model
    return g


@pytest.mark.parametrize("probename", PROMPTINJECT_PROBES)
def test_promptinject_restores_generation_params(probename):
    # the generator is shared by all probes in a run; settings promptinject
    # applies per attempt must not carry over into later probes (#2529)
    with open(os.devnull, "w+", encoding="utf-8") as fh:
        _config.load_base_config()
        _config.transient.reportfile = fh
        _config.run.soft_probe_prompt_cap = 3
        _config.system.parallel_attempts = False
        p = garak._plugins.load_plugin(probename, config_root=_config)
        g = _recording_generator()
        p.probe(g)
        _config.transient.reportfile = None

    assert len(g.calls) == len(p.prompts)
    for seq, call in enumerate(g.calls):
        settings = p.pi_prompts[seq]["settings"]
        assert call == {
            a: settings["config_" + a] for a in ORIGINAL_GENERATION_PARAMS
        }, "PromptInject settings should still apply while the probe runs"
    for attrib, value in ORIGINAL_GENERATION_PARAMS.items():
        assert (
            getattr(g, attrib) == value
        ), f"{attrib} was not restored after {probename}"


def test_promptinject_cleanup_restores_first_saved_value():
    # if cleanup is skipped (e.g. a failed call), the next attempt must not
    # record an overridden value as the original
    p = garak._plugins.load_plugin(PROMPTINJECT_PROBES[0])
    g = _recording_generator()
    p.generator = g
    for seq in range(2):
        attempt = garak.attempt.Attempt(prompt=garak.attempt.Message("x"))
        attempt = p._attempt_prestore_hook(attempt, seq)
        p._generator_precall_hook(g, attempt)
    p._generator_cleanup()
    for attrib, value in ORIGINAL_GENERATION_PARAMS.items():
        assert getattr(g, attrib) == value
