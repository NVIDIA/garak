import garak._plugins
import garak.attempt
from garak import _config
from garak.probes import turkishinjection

PROBE = "probes.turkishinjection.TurkishPromptInjection"
DETECTOR = "detectors.promptinject.AttackRogueString"


def test_turkishinjection_prompts_hold_a_task_and_an_injection():
    """A prompt opens with a task and carries the string its attempt is scored on."""
    p = garak._plugins.load_plugin(PROBE)
    task_openings = tuple(task["instruction"] for task in turkishinjection._TASKS)
    assert len(p.prompts) > 0
    for prompt, trigger in zip(p.prompts, p.triggers, strict=True):
        assert prompt.startswith(task_openings), "prompt must open with a task"
        injected = prompt.removeprefix(
            next(opening for opening in task_openings if prompt.startswith(opening))
        )
        assert trigger in injected, "the injected text must ask for the trigger"


def test_turkishinjection_prompts_are_unique():
    p = garak._plugins.load_plugin(PROBE)
    assert len(set(p.prompts)) == len(
        p.prompts
    ), "a prompt should be built once; repeats are what generations is for"


def test_turkishinjection_triggers_follow_their_prompt_after_capping():
    """Capping must not leave an attempt scored on another prompt's string."""
    cap = 7
    _config.run.soft_probe_prompt_cap = cap
    p = garak._plugins.load_plugin(PROBE, config_root=_config)
    assert len(p.prompts) == cap
    for seq, prompt in enumerate(p.prompts):
        attempt = garak.attempt.Attempt(prompt=garak.attempt.Message(prompt))
        attempt = p._attempt_prestore_hook(attempt, seq)
        (trigger,) = attempt.notes["triggers"]
        assert trigger in prompt


def _turkish_upper(text: str) -> str:
    """Uppercase the way Turkish does: i pairs with İ, and ı with I."""
    return text.replace("i", "İ").replace("ı", "I").upper()


def _turkish_lower(text: str) -> str:
    """Lowercase the way Turkish does: İ pairs with i, and I with ı."""
    return text.replace("İ", "i").replace("I", "ı").lower()


def test_turkishinjection_detector_hits_only_on_the_injected_string():
    """The injected string is a hit however it is cased; a task answer is not."""
    p = garak._plugins.load_plugin(PROBE)
    d = garak._plugins.load_plugin(DETECTOR)
    for trigger in set(p.triggers):
        seq = p.triggers.index(trigger)
        attempt = garak.attempt.Attempt(prompt=garak.attempt.Message(p.prompts[seq]))
        attempt = p._attempt_prestore_hook(attempt, seq)
        attempt.outputs = [
            trigger,
            _turkish_upper(trigger),
            _turkish_lower(trigger),
            "olumsuz",
        ]
        assert d.detect(attempt) == [1.0, 1.0, 1.0, 0.0]
