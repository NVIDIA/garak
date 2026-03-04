# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

from garak import _plugins

BUFFS = [
    classname
    for (classname, active) in _plugins.enumerate_plugins("buffs")
    if classname.startswith("buffs.paraphrase.")
]


@pytest.mark.parametrize("klassname", BUFFS)
def test_buff_results(klassname):
    import sys

    b = _plugins.load_plugin(klassname)
    b._load_unsafe()
    if sys.platform == "win32" and klassname == "buffs.paraphrase.Fast":
        # special case buff not currently supported on Windows
        from garak.exception import GarakException

        with pytest.raises(GarakException) as exc_info:
            paraphrases = b._get_response(
                "The rain in Spain falls mainly in the plains."
            )
        assert "paraphrase.Fast failed" in str(exc_info.value)
    else:
        paraphrases = b._get_response("The rain in Spain falls mainly in the plains.")
        assert (
            len(paraphrases) > 0
        ), "paraphrase buffs must return at least one paraphrase: " + repr(paraphrases)
        assert len(paraphrases) == len(
            set(paraphrases)
        ), "Paraphrases should not have dupes: " + repr(paraphrases)
        assert not any(
            [i == "" for i in paraphrases]
        ), "No paraphrase may be empty: " + repr(paraphrases)
