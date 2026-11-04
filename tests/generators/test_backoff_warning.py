"""Tests for garak's rate-limit backoff warnings.

Covers garak.generators.base.log_backoff_event (visible warnings + run
totals when the provider throttles us) and the Retry-After surfacing in
garak.generators.rest.RestGenerator.
"""

import logging

import pytest

from garak import _config
from garak.attempt import Conversation, Message, Turn
from garak.exception import GeneratorBackoffTrigger, RateLimitHit
from garak.generators.base import log_backoff_event
from garak.generators.rest import RestGenerator

DEFAULT_NAME = "REST Test"
DEFAULT_URI = "https://www.wikidata.org/wiki/Q22971"


@pytest.fixture(autouse=True)
def reset_ratelimit_counters():
    _config.transient.ratelimit_retries = 0
    _config.transient.ratelimit_wait_seconds = 0.0
    yield
    _config.transient.ratelimit_retries = 0
    _config.transient.ratelimit_wait_seconds = 0.0


@pytest.fixture
def set_rest_config():
    _config.run.user_agent = "test user agent, garak.ai"
    _config.plugins.generators["rest"] = {}
    _config.plugins.generators["rest"]["RestGenerator"] = {
        "name": DEFAULT_NAME,
        "uri": DEFAULT_URI,
        "api_key": "testing",
    }


def test_backoff_handler_counts_ratelimit(caplog):
    details = {
        "wait": 3.5,
        "tries": 2,
        "exception": RateLimitHit("Rate limited: 429"),
    }
    with caplog.at_level(logging.WARNING):
        log_backoff_event(details)
    assert _config.transient.ratelimit_retries == 1
    assert _config.transient.ratelimit_wait_seconds == 3.5
    assert "waiting 3.5s before retry #2" in caplog.text


def test_backoff_handler_warns_but_does_not_count_other_triggers(caplog):
    details = {
        "wait": 1.0,
        "tries": 1,
        "exception": GeneratorBackoffTrigger("server hiccup"),
    }
    with caplog.at_level(logging.WARNING):
        log_backoff_event(details)
    assert _config.transient.ratelimit_retries == 0
    assert _config.transient.ratelimit_wait_seconds == 0.0
    assert "waiting 1.0s before retry #1" in caplog.text


@pytest.mark.usefixtures("set_rest_config")
def test_ratelimit_message_includes_retry_after(requests_mock):
    requests_mock.post(
        DEFAULT_URI, status_code=429, headers={"Retry-After": "30"}
    )
    generator = RestGenerator()
    conv = Conversation([Turn("user", Message("sup REST"))])
    # call the undecorated method: the backoff wrapper would retry forever
    with pytest.raises(RateLimitHit) as excinfo:
        generator._call_model.__wrapped__(generator, conv)
    assert "retry-after: 30s" in str(excinfo.value)


@pytest.mark.usefixtures("set_rest_config")
def test_ratelimit_message_without_retry_after(requests_mock):
    requests_mock.post(DEFAULT_URI, status_code=429)
    generator = RestGenerator()
    conv = Conversation([Turn("user", Message("sup REST"))])
    with pytest.raises(RateLimitHit) as excinfo:
        generator._call_model.__wrapped__(generator, conv)
    assert "Rate limited: 429" in str(excinfo.value)
    assert "retry-after" not in str(excinfo.value)
