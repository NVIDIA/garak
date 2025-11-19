from garak import _config, _plugins
from garak.probes.badchars import DEFAULT_INVISIBLE, BIDI_CONTROLS


PLUGIN_NAME = "probes.badchars.BadCharacters"


def _load_badcharacters(custom_config: dict | None = None):
    cfg = {"probes": {"badchars": {"BadCharacters": custom_config or {}}}}
    return _plugins.load_plugin(PLUGIN_NAME, config_root=cfg)


def test_badcharacters_generates_all_categories():
    original_cap = _config.run.soft_probe_prompt_cap
    _config.run.soft_probe_prompt_cap = None
    try:
        probe = _load_badcharacters(
            {
                "perturbation_budget": 1,
                "max_position_candidates": 2,
                "max_reorder_candidates": 2,
                "max_ascii_variants": 4,
                "follow_prompt_cap": False,
            }
        )
    finally:
        _config.run.soft_probe_prompt_cap = original_cap

    categories = {conv.notes.get("bad_character_category") for conv in probe.prompts}
    assert {"invisible", "homoglyph", "reordering", "deletion"}.issubset(categories)

    for conv in probe.prompts:
        assert isinstance(conv.notes.get("operations"), dict)
        assert conv.notes.get("source_payload_index") is not None
        assert conv.notes.get("source_payload_excerpt")


def test_badcharacters_respects_prompt_cap():
    original_cap = _config.run.soft_probe_prompt_cap
    _config.run.soft_probe_prompt_cap = 5
    try:
        probe = _load_badcharacters(
            {
                "perturbation_budget": 1,
                "max_position_candidates": 2,
                "max_reorder_candidates": 2,
                "max_ascii_variants": 3,
            }
        )
    finally:
        _config.run.soft_probe_prompt_cap = original_cap

    assert len(probe.prompts) <= 5

    categories = {conv.notes.get("bad_character_category") for conv in probe.prompts}
    assert categories  # non-empty after downsampling


def test_badcharacters_inserts_expected_characters():
    probe = _load_badcharacters(
        {
            "perturbation_budget": 1,
            "max_position_candidates": 2,
            "max_reorder_candidates": 2,
            "max_ascii_variants": 2,
            "follow_prompt_cap": False,
        }
    )

    samples = {}
    for conv in probe.prompts:
        category = conv.notes.get("bad_character_category")
        samples.setdefault(category, conv)

    assert {"invisible", "homoglyph", "reordering", "deletion"}.issubset(samples.keys())

    invisible_text = samples["invisible"].turns[0].content.text
    assert any(ch in DEFAULT_INVISIBLE for ch in invisible_text)

    homoglyph_conv = samples["homoglyph"]
    homoglyph_text = homoglyph_conv.turns[0].content.text
    replacements = homoglyph_conv.notes["operations"]["replacements"]
    for replacement in replacements:
        assert replacement in homoglyph_text

    reorder_text = samples["reordering"].turns[0].content.text
    assert any(ctrl in reorder_text for ctrl in BIDI_CONTROLS.values())

    deletion_conv = samples["deletion"]
    deletion_text = deletion_conv.turns[0].content.text
    ascii_codes = deletion_conv.notes["operations"]["ascii_codes"]
    for code in ascii_codes:
        seq = f"{chr(code)}\b"
        assert seq in deletion_text
