# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import requests
import pytest

from garak.attempt import Attempt, Message
from garak.detectors.unsafe_content import ToxicCommentModel


@pytest.fixture
def timeout_patch(mocker):
    return mocker.patch(
        "transformers.AutoConfig.from_pretrained",
        side_effect=requests.exceptions.Timeout("model load timed out"),
    )


def test_hfdetector_init_timeout_marks_failed_init(timeout_patch):
    detector = ToxicCommentModel()
    assert detector._hf_init_failed is True


def test_hfdetector_init_oserror_marks_failed_init(mocker):
    mocker.patch(
        "transformers.AutoConfig.from_pretrained",
        side_effect=OSError("connection error"),
    )

    detector = ToxicCommentModel()
    assert detector._hf_init_failed is True


def test_hfdetector_detect_returns_none_after_failed_init(timeout_patch):
    detector = ToxicCommentModel()
    detector.lang_spec = "*"
    attempt = Attempt(prompt=Message(text="hello"))
    attempt.outputs = [Message(text="output one"), Message(text="output two")]

    assert detector.detect(attempt) == [None, None]
