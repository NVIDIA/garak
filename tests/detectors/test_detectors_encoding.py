# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import garak._plugins
from garak.attempt import Attempt


TEST_TEXT = "match"
TEST_TEXT2 = "cardassia"
NOT_TEST_TEXT = "kjasfhg"
LONG_TEST_TEXT = "terriblewords"
LONG_TEST_TEXT_CORRUPT = "terri^blewords"


def test_decodematch():
    d = garak._plugins.load_plugin("detectors.encoding.DecodeMatch")

    a = Attempt(prompt="test text", lang=d.lang_spec.split(",")[0])
    a.notes["triggers"] = [TEST_TEXT]
    a.outputs = [TEST_TEXT]

    result = d.detect(a)
    assert result == [1.0], "DecodeMatch should record his when trigger text is present"

    a.outputs = [NOT_TEST_TEXT]
    result = d.detect(a)
    assert (
        result[-1] == 0.0
    ), "DecodeMatch should not record hit when trigger text isn't present"

    a.outputs = [TEST_TEXT + " " + NOT_TEST_TEXT]
    result = d.detect(a)
    assert (
        result[-1] == 1.0
    ), "DecodeMatch should record hit when trigger text is present"

    a.notes["triggers"] = [TEST_TEXT, TEST_TEXT2]

    a.outputs = [NOT_TEST_TEXT + " " + TEST_TEXT2]
    result = d.detect(a)
    assert (
        result[-1] == 1.0
    ), "DecodeMatch should record hit when one of many trigger texts is present"

    a.outputs = [NOT_TEST_TEXT + " " + TEST_TEXT]
    result = d.detect(a)
    assert (
        result[-1] == 1.0
    ), "DecodeMatch should record hit when any of many trigger texts is present"


def test_decodeapprox():
    d = garak._plugins.load_plugin("detectors.encoding.DecodeApprox")

    a = Attempt(prompt="test text", lang=d.lang_spec.split(",")[0])
    a.notes["triggers"] = [TEST_TEXT]
    a.outputs = [TEST_TEXT]

    result = d.detect(a)
    assert result == [1.0], "DecodeApprox should reach 1.0 output matches trigger text"

    a.outputs = [NOT_TEST_TEXT]
    result = d.detect(a)
    assert (
        result[-1] == 0.0
    ), "DecodeApprox should record zero when no match text present"

    a.outputs = [TEST_TEXT + " " + NOT_TEST_TEXT]
    result = d.detect(a)
    assert (
        result[-1] > 0.5
    ), "DecodeApprox should record hit when trigger text is present"

    a.outputs = [TEST_TEXT[0 : d.n - 1]]
    result = d.detect(a)
    assert (
        result[-1] == 0.0
    ), "DecodeApprox should return 0.0 when output is shorter than match"

    a.notes["triggers"] = [LONG_TEST_TEXT]

    a.outputs = [LONG_TEST_TEXT_CORRUPT]
    result = d.detect(a)
    assert (
        result[-1] > 0.5
    ), "DecodeApprox should record hit when corrupted trigger text is present"

    a.notes["triggers"] = [TEST_TEXT, TEST_TEXT2]

    a.outputs = [NOT_TEST_TEXT + " " + TEST_TEXT2]
    result = d.detect(a)
    assert (
        result[-1] > 0.5
    ), "DecodeApprox should record hit when one of many trigger texts is present"

    a.outputs = [NOT_TEST_TEXT + " " + TEST_TEXT]
    result = d.detect(a)
    assert (
        result[-1] > 0.5
    ), "DecodeApprox should record hit when any of many trigger texts is present"
