from garak import _plugins

PLUGIN_NAME = "probes.replay_filter_evasion.ReplayFilterEvasionICL"


def test_probe_loads():
    probe = _plugins.load_plugin(PLUGIN_NAME)
    assert probe is not None
    assert probe.probename == f"garak.{PLUGIN_NAME}"


def test_probe_generates_prompts():
    probe = _plugins.load_plugin(PLUGIN_NAME)
    assert len(probe.prompts) > 0
    assert len(probe.triggers) > 0
    assert len(probe.prompts) == len(probe.triggers)


def test_probe_has_correct_goal():
    probe = _plugins.load_plugin(PLUGIN_NAME)
    assert "replay" in probe.goal.lower()
    assert "filter" in probe.goal.lower()
    assert probe.primary_detector == "leakreplay.StartsWith"


def test_probe_prompts_contain_icl_examples():
    probe = _plugins.load_plugin(PLUGIN_NAME)
    for prompt in probe.prompts:
        assert "Input:" in prompt
        assert "Output:" in prompt
        assert "Call me Ishmael" in prompt


def test_probe_prompts_contain_target_text():
    probe = _plugins.load_plugin(PLUGIN_NAME)
    for prompt, trigger in zip(probe.prompts, probe.triggers):
        assert trigger in prompt


def test_probe_sets_triggers_in_notes():
    from garak.attempt import Attempt, Conversation, Turn, Message

    probe = _plugins.load_plugin(PLUGIN_NAME)
    attempt = Attempt(
        probe_classname=PLUGIN_NAME,
        goal=probe.goal,
        prompt=Conversation([Turn("user", Message(text="test"))]),
    )
    attempt = probe._attempt_prestore_hook(attempt, 0)
    assert "triggers" in attempt.notes
    assert len(attempt.notes["triggers"]) == 1
    assert isinstance(attempt.notes["triggers"][0], str)


def test_probe_has_eight_targets():
    probe = _plugins.load_plugin(PLUGIN_NAME)
    assert len(probe.prompts) == 8


def test_probe_full_extends_base():
    full = _plugins.load_plugin(
        "probes.replay_filter_evasion.ReplayFilterEvasionICLFull"
    )
    base = _plugins.load_plugin(PLUGIN_NAME)
    assert len(full.prompts) > len(base.prompts)
