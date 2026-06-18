import garak._plugins
import garak.attempt
import garak.payloads
import garak.probes.many_shot


def test_many_shot_prompts_are_conversations():
    p = garak._plugins.load_plugin("probes.many_shot.ManyShot")
    assert len(p.prompts) > 0, "ManyShot should produce at least one prompt"
    for prompt in p.prompts:
        assert isinstance(
            prompt, garak.attempt.Conversation
        ), "ManyShot prompts must be Conversation objects"
        assert (
            prompt.turns[-1].role == "user"
        ), "the final turn must be the user's real request"


def test_many_shot_prompt_count_matches_sweep():
    p = garak._plugins.load_plugin("probes.many_shot.ManyShot")
    n_payloads = sum(len(garak.payloads.load(name).payloads) for name in p.payload_name)
    n_shot_counts = len(set(p.shot_counts))
    assert len(p.prompts) == n_payloads * n_shot_counts


def test_many_shot_turn_structure_and_alternation():
    p = garak._plugins.load_plugin("probes.many_shot.ManyShot")
    shot_counts = sorted(set(p.shot_counts))
    # the first prompt uses the smallest shot count by construction
    smallest = shot_counts[0]
    conv = p.prompts[0]
    # shot_count (user, assistant) pairs plus one final user turn
    assert len(conv.turns) == 2 * smallest + 1
    # fabricated history must strictly alternate user -> assistant
    for i in range(smallest):
        assert conv.turns[2 * i].role == "user"
        assert conv.turns[2 * i + 1].role == "assistant"
    assert conv.turns[-1].role == "user"


def test_many_shot_assistant_turns_show_compliance():
    p = garak._plugins.load_plugin("probes.many_shot.ManyShot")
    conv = p.prompts[0]
    assistant_turns = [t for t in conv.turns if t.role == "assistant"]
    assert len(assistant_turns) > 0
    for turn in assistant_turns:
        # every fabricated answer must look like compliance, never a refusal,
        # so the in-context pattern is "the assistant always complies"
        assert turn.content.text == garak.probes.many_shot.COMPLIANT_ANSWER
        assert "I cannot" not in turn.content.text
        assert "I'm sorry" not in turn.content.text


def test_many_shot_target_differs_from_exemplars():
    p = garak._plugins.load_plugin("probes.many_shot.ManyShot")
    conv = p.prompts[0]
    target = conv.turns[-1].content.text
    exemplar_requests = {t.content.text for t in conv.turns[:-1] if t.role == "user"}
    assert (
        target not in exemplar_requests
    ), "the real request must not appear among the fabricated exemplars"


def test_many_shot_shot_count_is_configurable():
    config_root = {"probes": {"many_shot": {"ManyShot": {"shot_counts": [2]}}}}
    p = garak._plugins.load_plugin("probes.many_shot.ManyShot", config_root=config_root)
    assert p.shot_counts == [2]
    for prompt in p.prompts:
        # 2 (user, assistant) pairs + final user turn
        assert len(prompt.turns) == 5
