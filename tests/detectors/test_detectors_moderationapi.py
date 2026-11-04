import pytest
import requests

from garak.attempt import Attempt, Message
import garak.detectors.moderationapi

URI = "https://api.moderationapi.com/v1/moderate"
DETECTOR_CLASSES = [
    c["name"] for c in garak.detectors.moderationapi.moderationapi_classes
]


def _response(scores):
    return {
        "policies": [
            {"id": policy, "type": "classifier", "probability": p, "flagged": p > 0.5}
            for policy, p in scores.items()
        ]
    }


def _detector(classname):
    return getattr(garak.detectors.moderationapi, classname)()


def _attempt(outputs):
    a = Attempt(prompt=Message("test prompt", lang="en"))
    a.outputs = outputs
    return a


@pytest.fixture(autouse=True)
def api_key(monkeypatch):
    monkeypatch.setenv("MODERATION_API_KEY", "test-key")


@pytest.fixture(autouse=True)
def no_backoff_wait(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda _: None)


@pytest.mark.parametrize("classname", DETECTOR_CLASSES)
def test_returns_own_policy_score(classname, requests_mock):
    d = _detector(classname)
    scores = {
        c["policy"]: 0.1 * (i + 1)
        for i, c in enumerate(garak.detectors.moderationapi.moderationapi_classes)
    }
    requests_mock.post(URI, json=_response(scores))

    results = d.detect(_attempt(["some output"]))

    assert results == [
        scores[d.policy]
    ], "detector should return its own policy probability"
    request = requests_mock.last_request
    assert (
        request.headers["Authorization"] == "Bearer test-key"
    ), "key should be sent as bearer token"
    assert request.json() == {
        "content": {"type": "text", "text": "some output"},
        "doNotStore": True,
    }, "request body should carry output text and ask not to store it"


def test_empty_and_missing_outputs(requests_mock):
    d = _detector("Toxicity")
    requests_mock.post(URI, json=_response({"toxicity": 0.9}))

    results = d.detect(_attempt(["", None, Message()]))

    assert results == [
        0.0,
        None,
        None,
    ], "empty text scores 0.0, missing outputs relay None"
    assert not requests_mock.called, "no request should be sent without text to score"


def test_policy_absent_from_response(requests_mock):
    d = _detector("Threat")
    requests_mock.post(URI, json=_response({"toxicity": 0.9}))

    assert d.detect(_attempt(["some output"])) == [
        None
    ], "a policy not enabled should give None"


@pytest.mark.parametrize("status", [429, 503])
def test_backs_off_on_rate_limit_and_server_error(status, requests_mock):
    d = _detector("Toxicity")
    requests_mock.post(
        URI,
        [
            {"status_code": status, "json": {}},
            {"status_code": 200, "json": _response({"toxicity": 0.7})},
        ],
    )

    assert d.detect(_attempt(["some output"])) == [
        0.7
    ], "detector should retry after backoff"
    assert requests_mock.call_count == 2


def test_rejected_key_raises(requests_mock):
    d = _detector("Toxicity")
    requests_mock.post(URI, status_code=401, json={})

    with pytest.raises(requests.exceptions.HTTPError):
        d.detect(_attempt(["some output"]))
    assert requests_mock.call_count == 1, "auth errors should not be retried"
