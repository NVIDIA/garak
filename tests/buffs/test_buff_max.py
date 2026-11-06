from collections import Counter

import pytest

from garak import _config
import garak._plugins
import garak.attempt


@pytest.mark.parametrize("with_seq", [True, False], ids=["seq", "no_seq"])
def test_buff_max_caps_buffed_attempts_per_input_attempt(with_seq):
    # tree-search probes mint attempts without a seq, so the cap must not rely on it
    _config.load_base_config()
    probe = garak._plugins.load_plugin("probes.test.Test")
    buffs = [
        garak._plugins.load_plugin(name)
        for name in (
            "buffs.lowercase.Lowercase",
            "buffs.encoding.Base64",
            "buffs.encoding.CharCode",
        )
    ]
    _config.buffmanager.buffs = buffs
    _config.plugins.buffs_include_original_prompt = False
    _config.plugins.buff_max = 2
    try:
        attempts = [
            probe._mint_attempt(f"Prompt {i}", seq=i if with_seq else None, lang="en")
            for i in range(5)
        ]
        buffed = list(probe._buff_hook(attempts))
    finally:
        _config.buffmanager.buffs = []
        _config.plugins.buff_max = None
    # every input attempt gets buff_max buffed attempts, from the first buffs in order
    per_source = Counter(a.notes["buff_source_attempt_uuid"] for a in buffed)
    assert per_source == {str(a.uuid): 2 for a in attempts}
