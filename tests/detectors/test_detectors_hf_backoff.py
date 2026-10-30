# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Backoff retry for HF Hub detector model loads (issue #1479).

`transformers` re-raises Hub fetch failures as plain `OSError`, so these
tests pin both the giveup predicate used by the `backoff` decorator and the
retry behaviour of `HFDetector._load_detector_model`. All network access is
mocked; no model is downloaded.
"""

from types import SimpleNamespace

import pytest

from garak.detectors.base import HFDetector
from garak.resources.api.huggingface import hf_hub_backoff_giveup


def _hub_error(status_code):
    from huggingface_hub.errors import HfHubHTTPError

    return HfHubHTTPError(
        f"{status_code} Server Error for url: https://huggingface.co/api/models/x",
        response=SimpleNamespace(
            headers={}, request=None, status_code=status_code
        ),
    )


def _wrapped_hub_error_chained(status_code):
    hub_error = _hub_error(status_code)
    try:
        raise hub_error
    except Exception as chained:
        try:
            raise OSError(
                f"There was a specific connection error when trying to load repo:\n{chained}"
            ) from chained
        except OSError as wrapped:
            return wrapped


@pytest.mark.parametrize("status_code", [429, 500, 502, 503, 504])
def test_giveup_retries_transient_hub_status(status_code):
    assert hf_hub_backoff_giveup(_hub_error(status_code)) is False


@pytest.mark.parametrize("status_code", [400, 401, 403, 404])
def test_giveup_raises_immediately_on_permanent_hub_status(status_code):
    assert hf_hub_backoff_giveup(_hub_error(status_code)) is True


def test_giveup_retries_transformers_wrapped_503():
    assert hf_hub_backoff_giveup(_wrapped_hub_error_chained(503)) is False


def test_giveup_raises_immediately_on_transformers_wrapped_404():
    assert hf_hub_backoff_giveup(_wrapped_hub_error_chained(404)) is True


def test_giveup_connection_errors_retry_other_errors_raise():
    assert hf_hub_backoff_giveup(ConnectionError("dropped")) is False
    assert hf_hub_backoff_giveup(TimeoutError("timed out")) is False
    assert hf_hub_backoff_giveup(ValueError("bad config")) is True


def _detector_stub():
    detector = HFDetector.__new__(HFDetector)
    detector.detector_model_path = "some-org/some-model"
    detector.device = "cpu"
    return detector


def _patch_transformers(monkeypatch, config_fake, model_fake, tokenizer_fake):
    import transformers

    monkeypatch.setattr(
        transformers.AutoConfig, "from_pretrained", config_fake
    )
    monkeypatch.setattr(
        transformers.AutoModelForSequenceClassification,
        "from_pretrained",
        model_fake,
    )
    monkeypatch.setattr(
        transformers.AutoTokenizer, "from_pretrained", tokenizer_fake
    )
    monkeypatch.setattr("time.sleep", lambda seconds: None)


def test_load_retries_transient_then_succeeds(monkeypatch):
    calls = {"config": 0}

    def flaky_config(path, **kwargs):
        calls["config"] += 1
        if calls["config"] < 3:
            raise _wrapped_hub_error_chained(503)
        return SimpleNamespace()

    model_stub = SimpleNamespace()
    model_stub.to = lambda device: model_stub
    _patch_transformers(
        monkeypatch,
        flaky_config,
        lambda path, **kwargs: model_stub,
        lambda path, **kwargs: SimpleNamespace(),
    )

    detector = _detector_stub()
    detector._load_detector_model({})

    assert calls["config"] == 3, "transient 503s should be retried, then succeed"
    assert detector.detector_model is model_stub
    assert detector.detector_tokenizer is not None


def test_load_gives_up_immediately_on_404(monkeypatch):
    calls = {"config": 0}

    def missing_repo(path, **kwargs):
        calls["config"] += 1
        raise _wrapped_hub_error_chained(404)

    _patch_transformers(
        monkeypatch,
        missing_repo,
        lambda path, **kwargs: SimpleNamespace(),
        lambda path, **kwargs: SimpleNamespace(),
    )

    with pytest.raises(OSError):
        _detector_stub()._load_detector_model({})
    assert calls["config"] == 1, "permanent 404 must not be retried"


def test_load_gives_up_after_max_tries_on_persistent_503(monkeypatch):
    calls = {"config": 0}

    def always_down(path, **kwargs):
        calls["config"] += 1
        raise _wrapped_hub_error_chained(503)

    _patch_transformers(
        monkeypatch,
        always_down,
        lambda path, **kwargs: SimpleNamespace(),
        lambda path, **kwargs: SimpleNamespace(),
    )

    with pytest.raises(OSError):
        _detector_stub()._load_detector_model({})
    assert calls["config"] == 5, "persistent 503 must exhaust bounded retries"
