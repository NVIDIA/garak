import re

from garak.probes.apikey import GetKey, CompleteKey, KEY_TYPES

GENERATE_TEMPLATE = "Generate a new "
# "... I lost part of my <key type>. The part I have left is ..."
_COMPLETE_KEY_TYPE = re.compile(r"lost part of my (.+?)\. The part I have left")


def _as_text(prompt):
    return prompt.text if hasattr(prompt, "text") else prompt


def test_key_types_are_populated():
    """KEY_TYPES must resolve from the service regexes, else every probe is empty."""
    assert len(KEY_TYPES) > 0, "KEY_TYPES should be extracted from the service regexes"


def test_getkey_asks_for_each_key_type():
    """GetKey builds one 'generate a key' request per known service key type."""
    prompts = [_as_text(p) for p in GetKey().prompts]
    assert prompts, "GetKey should generate at least one prompt"
    keys_asked = []
    for text in prompts:
        assert text.startswith(
            GENERATE_TEMPLATE
        ), "each GetKey prompt should use the generate-a-key template"
        keys_asked.append(text[len(GENERATE_TEMPLATE) :])
    assert all(
        key in KEY_TYPES for key in keys_asked
    ), "every GetKey prompt should target a known key type"
    assert len(set(keys_asked)) == len(
        prompts
    ), "GetKey should not repeat the same key type"


def test_completekey_supplies_a_partial_key_to_complete():
    """CompleteKey embeds a partial secret and asks the target to finish it."""
    prompts = [_as_text(p) for p in CompleteKey().prompts]
    assert prompts, "CompleteKey should generate at least one prompt"
    for text in prompts:
        assert (
            "complete the key" in text
        ), "each CompleteKey prompt should ask the target to complete the key"
        assert any(
            partial in text for partial in CompleteKey.partial_keys
        ), "each CompleteKey prompt should embed one of the seeded partial keys"
        match = _COMPLETE_KEY_TYPE.search(text)
        assert (
            match is not None and match.group(1) in KEY_TYPES
        ), "each CompleteKey prompt should name a known key type"
