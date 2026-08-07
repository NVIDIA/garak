# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

import garak._plugins
from garak.attempt import Attempt, Message

TEST_TEXT = "match"
TEST_TEXT2 = "cardassia"
NOT_TEST_TEXT = "kjasfhg"
LONG_TEST_TEXT = "terriblewords"
LONG_TEST_TEXT_CORRUPT = "terri^blewords"


def _make_attempt(detector, triggers, outputs):
    a = Attempt(prompt=Message(text="test text", lang=detector.lang_spec.split(",")[0]))
    a.notes["triggers"] = triggers
    a.outputs = [Message(o) for o in outputs]
    return a


class TestDecodeMatch:
    @pytest.fixture
    def detector(self):
        return garak._plugins.load_plugin("detectors.encoding.DecodeMatch")

    def test_hit_when_trigger_present(self, detector):
        a = _make_attempt(detector, [TEST_TEXT], [TEST_TEXT])
        assert detector.detect(a) == [
            1.0
        ], "should score 1.0 when trigger text is present in output"

    def test_no_hit_when_trigger_absent(self, detector):
        a = _make_attempt(detector, [TEST_TEXT], [NOT_TEST_TEXT])
        assert detector.detect(a) == [
            0.0
        ], "should score 0.0 when trigger text is absent from output"

    def test_hit_when_trigger_is_substring(self, detector):
        a = _make_attempt(detector, [TEST_TEXT], [TEST_TEXT + " " + NOT_TEST_TEXT])
        assert detector.detect(a) == [
            1.0
        ], "should score 1.0 when trigger appears as a substring of the output"

    def test_hit_when_one_of_many_triggers_present(self, detector):
        a = _make_attempt(
            detector, [TEST_TEXT, TEST_TEXT2], [NOT_TEST_TEXT + " " + TEST_TEXT2]
        )
        assert detector.detect(a) == [
            1.0
        ], "should score 1.0 when any one of multiple triggers is present"

    def test_hit_when_any_of_many_triggers_present(self, detector):
        a = _make_attempt(
            detector, [TEST_TEXT, TEST_TEXT2], [NOT_TEST_TEXT + " " + TEST_TEXT]
        )
        assert detector.detect(a) == [
            1.0
        ], "should score 1.0 regardless of which trigger in the list matches"

    def test_case_insensitive_matches_different_case(self, detector):
        detector.case_sensitive = False
        a = _make_attempt(detector, [TEST_TEXT], [TEST_TEXT.upper()])
        assert detector.detect(a) == [
            1.0
        ], "should match when casing differs and case_sensitive is False"

    def test_case_sensitive_rejects_different_case(self, detector):
        detector.case_sensitive = True
        a = _make_attempt(detector, [TEST_TEXT], [TEST_TEXT.upper()])
        assert detector.detect(a) == [
            0.0
        ], "should reject when casing differs and case_sensitive is True"

    def test_case_sensitive_accepts_exact_match(self, detector):
        detector.case_sensitive = True
        a = _make_attempt(detector, [TEST_TEXT], [TEST_TEXT])
        assert detector.detect(a) == [
            1.0
        ], "should match when casing is identical and case_sensitive is True"


class TestDecodeApprox:
    @pytest.fixture
    def detector(self):
        return garak._plugins.load_plugin("detectors.encoding.DecodeApprox")

    def test_exact_match_scores_one(self, detector):
        a = _make_attempt(detector, [TEST_TEXT], [TEST_TEXT])
        assert detector.detect(a) == [
            1.0
        ], "should score 1.0 when output exactly matches the trigger"

    def test_no_match_scores_zero(self, detector):
        a = _make_attempt(detector, [TEST_TEXT], [NOT_TEST_TEXT])
        assert detector.detect(a) == [
            0.0
        ], "should score 0.0 when output shares no n-grams with the trigger"

    def test_partial_match_scores_above_half(self, detector):
        a = _make_attempt(detector, [TEST_TEXT], [TEST_TEXT + " " + NOT_TEST_TEXT])
        assert (
            detector.detect(a)[-1] > 0.5
        ), "should score above 0.5 when trigger text is embedded in longer output"

    def test_short_output_scores_zero(self, detector):
        a = _make_attempt(detector, [TEST_TEXT], [TEST_TEXT[0 : detector.n - 1]])
        assert detector.detect(a) == [
            0.0
        ], "should score 0.0 when trigger is shorter than the n-gram window"

    def test_corrupted_trigger_scores_above_half(self, detector):
        a = _make_attempt(detector, [LONG_TEST_TEXT], [LONG_TEST_TEXT_CORRUPT])
        assert (
            detector.detect(a)[-1] > 0.5
        ), "should score above 0.5 for a lightly corrupted version of the trigger"

    def test_hit_when_one_of_many_triggers_present(self, detector):
        a = _make_attempt(
            detector, [TEST_TEXT, TEST_TEXT2], [NOT_TEST_TEXT + " " + TEST_TEXT2]
        )
        assert (
            detector.detect(a)[-1] > 0.5
        ), "should score above 0.5 when any one of multiple triggers is present"

    def test_hit_when_any_of_many_triggers_present(self, detector):
        a = _make_attempt(
            detector, [TEST_TEXT, TEST_TEXT2], [NOT_TEST_TEXT + " " + TEST_TEXT]
        )
        assert (
            detector.detect(a)[-1] > 0.5
        ), "should score above 0.5 regardless of which trigger in the list matches"

    def test_case_insensitive_matches_different_case(self, detector):
        detector.case_sensitive = False
        a = _make_attempt(detector, [LONG_TEST_TEXT], [LONG_TEST_TEXT.upper()])
        assert detector.detect(a) == [
            1.0
        ], "should score 1.0 when casing differs and case_sensitive is False"

    def test_case_sensitive_rejects_different_case(self, detector):
        detector.case_sensitive = True
        a = _make_attempt(detector, [LONG_TEST_TEXT], [LONG_TEST_TEXT.upper()])
        assert detector.detect(a) == [
            0.0
        ], "should score 0.0 when casing differs and case_sensitive is True"

    def test_case_sensitive_accepts_exact_match(self, detector):
        detector.case_sensitive = True
        a = _make_attempt(detector, [LONG_TEST_TEXT], [LONG_TEST_TEXT])
        assert detector.detect(a) == [
            1.0
        ], "should score 1.0 when casing is identical and case_sensitive is True"
