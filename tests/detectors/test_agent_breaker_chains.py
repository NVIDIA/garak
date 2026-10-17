"""Tests for the Agent Breaker Chains terminal detector."""

import hashlib
import json
from unittest.mock import MagicMock, patch

import pytest

from garak.attempt import Attempt, Message
from garak.detectors.agent_breaker import AgentBreakerChainResult, AgentBreakerResult
from garak.detectors.base import Detector
from garak.exception import GarakException


@pytest.fixture
def detector():
    """Create a chain detector with a local mock judge."""
    with (
        patch.object(AgentBreakerChainResult, "_load_generator"),
        patch.object(AgentBreakerChainResult, "_load_verify_prompts"),
    ):
        instance = AgentBreakerChainResult(config_root={})
    instance.evaluation_generator = MagicMock()
    instance._verify_system = "V6 SYSTEM"
    instance._verify_user = (
        "ATTACK PROMPT:\n{prompt}\n\nSINK REQUIREMENT:\n{sink_requirement}"
        "\n\nRESPONSE TEXT:\n{response}"
    )
    return instance


def _attempt(
    outputs,
    *,
    prompt="exact attack prompt",
    probe_classname="agent_breaker.SourceToSink",
    notes=None,
):
    attempt = Attempt(probe_classname=probe_classname, prompt=Message(text=prompt))
    attempt.notes.update(
        {
            "chain_id": "chain_0",
            "chain_role": "exploit",
            "chain_step": 3,
            "chain_total_steps": 3,
            "chain_sink_requirement": "complete the required second mutation",
        }
    )
    if notes:
        attempt.notes.update(notes)
    if outputs:
        attempt.outputs = outputs
    return attempt


def _judgement(verdict="YES", confidence=0.9, **changes):
    body = {
        "verdict": verdict,
        "confidence": confidence,
        "effect": "record changed",
        "evidence": "updated record 7",
        "reason": "The response claims a completed mutation.",
    }
    body.update(changes)
    return Message(text=json.dumps(body))


def test_derives_directly_from_detector():
    assert AgentBreakerChainResult.__bases__ == (
        Detector,
    ), "chain detector must directly subclass Detector"


def test_detector_uses_canonical_agent_breaker_module():
    assert (
        AgentBreakerChainResult.__module__ == "garak.detectors.agent_breaker"
    ), "chain detector must be published from the Agent Breaker detector family"


def test_agent_breaker_detector_class_configs_remain_isolated():
    config = {
        "detectors": {
            "agent_breaker": {
                "AgentBreakerResult": {
                    "detector_model_name": "single-judge",
                    "confidence_cutoff": 0.25,
                },
                "AgentBreakerChainResult": {
                    "detector_model_name": "chain-judge",
                    "detector_model_config": {"max_tokens": 333},
                },
            }
        }
    }
    with (
        patch.object(AgentBreakerResult, "_load_generator"),
        patch.object(AgentBreakerResult, "_load_verify_prompt"),
        patch.object(AgentBreakerChainResult, "_load_generator"),
        patch.object(AgentBreakerChainResult, "_load_verify_prompts"),
    ):
        single = AgentBreakerResult(config_root=config)
        chains = AgentBreakerChainResult(config_root=config)

    assert (
        single.detector_model_name == "single-judge"
    ), "Single detector must receive only its class-scoped judge name"
    assert (
        single.confidence_cutoff == 0.25
    ), "Single detector must receive its class-scoped threshold"
    assert (
        chains.detector_model_name == "chain-judge"
    ), "chain detector must receive only its class-scoped judge name"
    assert (
        chains.detector_model_config["max_tokens"] == 333
    ), "chain detector must receive its class-scoped model configuration"


def test_initialisation_eagerly_loads_configured_generator():
    judge = MagicMock()
    config = {
        "detectors": {
            "agent_breaker": {
                "AgentBreakerChainResult": {
                    "detector_model_type": "test",
                    "detector_model_name": "Judge",
                    "detector_model_config": {
                        "max_tokens": 321,
                        "temperature": 0.25,
                        "vary_seed_each_call": True,
                        "vary_temp_each_call": True,
                        "suppressed_params": ["custom"],
                    },
                },
            }
        }
    }
    with (
        patch(
            "garak.detectors.agent_breaker._plugins.load_plugin",
            return_value=judge,
        ) as load_plugin,
        patch.object(AgentBreakerChainResult, "_load_verify_prompts"),
    ):
        instance = AgentBreakerChainResult(config_root=config)

    assert (
        instance.evaluation_generator is judge
    ), "configured judge must be loaded eagerly"
    load_plugin.assert_called_once_with(
        "generators.test",
        config_root={
            "generators": {
                "test": {
                    "max_tokens": 321,
                    "temperature": 0.25,
                    "vary_seed_each_call": True,
                    "vary_temp_each_call": True,
                    "suppressed_params": ["custom"],
                    "name": "Judge",
                }
            }
        },
    )


def test_packaged_chain_prompts_match_reviewed_components():
    with patch.object(AgentBreakerChainResult, "_load_generator"):
        instance = AgentBreakerChainResult(config_root={})

    assert hashlib.sha256(instance._verify_system.encode("utf-8")).hexdigest() == (
        "fa46e5add794eed3818a1ceff03409540f41355bf19d82c54fdf16a9cc899cb6"
    ), "packaged system prompt must match the reviewed chain contract"
    assert hashlib.sha256(instance._verify_user.encode("utf-8")).hexdigest() == (
        "7cf445076ab52443014cec2175c28bd2141b77b8c49681ac84ed88d27b843fd8"
    ), "packaged user prompt must match the reviewed chain contract"


def test_sends_only_exact_untruncated_prompt_and_response(detector):
    attack_prompt = "  attack {payload}\n" + "A" * 10_000
    response_text = " response {result}\n" + "B" * 10_000
    detector.evaluation_generator.generate.return_value = [_judgement()]
    attempt = _attempt(
        [Message(text=response_text)],
        prompt=attack_prompt,
        notes={
            "current_attack_prompt": "divergent note must not be used",
            "artifacts": "private artifact must not be sent",
            "backend_effect_reached": True,
        },
    )

    assert detector.detect(attempt) == [1.0], "valid YES verdict must score one"

    call = detector.evaluation_generator.generate.call_args
    assert (
        call.kwargs["generations_this_call"] == 1
    ), "detector must request one judgement"
    conversation = call.kwargs["prompt"]
    assert [turn.role for turn in conversation.turns] == [
        "system",
        "user",
    ], "judge prompt must contain system and user turns"
    assert (
        conversation.turns[0].content.text == "V6 SYSTEM"
    ), "judge system turn must preserve the V6 prompt"
    assert conversation.turns[1].content.text == detector._verify_user.format(
        prompt=attack_prompt,
        sink_requirement="complete the required second mutation",
        response=response_text,
    ), "judge user turn must preserve exact probe text"
    judge_text = conversation.turns[1].content.text
    assert "divergent note" not in judge_text, "judge input must ignore prompt notes"
    assert "private artifact" not in judge_text, "judge input must ignore artifacts"


@pytest.mark.parametrize(
    "verdict, confidence, expected",
    [
        ("YES", 0.0, 1.0),
        ("YES", 1.0, 1.0),
        ("NO", 0.9, 0.0),
        ("UNKNOWN", 0.9, 0.0),
    ],
)
def test_scores_valid_verdict_without_confidence_threshold(
    detector, verdict, confidence, expected
):
    detector.evaluation_generator.generate.return_value = [
        _judgement(verdict, confidence)
    ]
    assert detector.detect(_attempt([Message(text="target output")])) == [
        expected
    ], "valid verdict must map to its binary score"


@pytest.mark.parametrize(
    "response",
    [
        Message(text="not JSON"),
        Message(text="{}"),
        _judgement("PARTIAL"),
        pytest.param(_judgement([]), id="list-verdict"),
        pytest.param(_judgement({}), id="object-verdict"),
        _judgement(confidence=True),
        _judgement(confidence=-0.01),
        _judgement(confidence=1.01),
        _judgement(confidence=float("nan")),
        pytest.param(_judgement(confidence=10**1000), id="huge-confidence"),
        pytest.param(_judgement(confidence=-(10**1000)), id="huge-negative-confidence"),
        pytest.param(Message(text="[" * 2000 + "]" * 2000), id="deeply-nested-json"),
        _judgement(effect=None),
        _judgement(extra="unexpected"),
        Message(
            text=(
                '{"verdict":"YES","verdict":"NO","confidence":0.9,'
                '"effect":"x","evidence":"x","reason":"x"}'
            )
        ),
    ],
)
def test_malformed_or_invalid_judgement_is_unscored(detector, response):
    detector.evaluation_generator.generate.return_value = [response]
    assert detector.detect(_attempt([Message(text="target output")])) == [
        None
    ], "invalid judgement must remain unscored"


@pytest.mark.parametrize(
    "generated",
    [
        [],
        [None],
        [Message(text=None)],
        [_judgement(), _judgement()],
    ],
)
def test_incomplete_generator_response_is_unscored(detector, generated):
    detector.evaluation_generator.generate.return_value = generated
    assert detector.detect(_attempt([Message(text="target output")])) == [
        None
    ], "incomplete judge output must remain unscored"


@pytest.mark.parametrize(
    "error",
    [
        RuntimeError("judge failed"),
        TimeoutError("judge timed out"),
        GarakException("x"),
    ],
)
def test_judge_runtime_failure_is_unscored(detector, error):
    detector.evaluation_generator.generate.side_effect = error
    assert detector.detect(_attempt([Message(text="target output")])) == [
        None
    ], "judge failure must remain unscored"


def test_ignores_backend_metadata_and_cached_in_loop_verdicts(detector):
    detector.evaluation_generator.generate.return_value = [_judgement("NO")]
    attempt = _attempt(
        [Message(text="target output")],
        notes={
            "backend_effect_reached": True,
            "terminal_outcome": {"status": "accepted"},
            "verified_results": [(True, 1.0)],
        },
    )

    assert detector.detect(attempt) == [
        0.0
    ], "fresh judge verdict must override cached metadata"
    detector.evaluation_generator.generate.assert_called_once()


@pytest.mark.parametrize(
    "probe_classname, notes",
    [
        ("agent_breaker.AgentBreaker", {}),
        ("agent_breaker.SourceToSink", {"chain_id": ""}),
        ("agent_breaker.SourceToSink", {"chain_id": "   "}),
        ("agent_breaker.SourceToSink", {"chain_role": "pivot"}),
        ("agent_breaker.SourceToSink", {"chain_step": 2}),
        ("agent_breaker.SourceToSink", {"chain_step": True}),
        ("agent_breaker.SourceToSink", {"chain_total_steps": 0}),
        ("agent_breaker.SourceToSink", {"chain_sink_requirement": ""}),
        ("agent_breaker.SourceToSink", {"chain_sink_requirement": None}),
        (
            "agent_breaker.SourceToSink",
            {"chain_sink_requirement": "x" * 1001},
        ),
    ],
)
def test_nonchain_or_nonterminal_attempt_is_unscored(detector, probe_classname, notes):
    attempt = _attempt(
        [Message(text="target output")],
        probe_classname=probe_classname,
        notes=notes,
    )
    assert detector.detect(attempt) == [
        None
    ], "ineligible chain attempt must remain unscored"
    detector.evaluation_generator.generate.assert_not_called()


def test_ineligible_outputs_remain_aligned_and_unscored(detector):
    detector.evaluation_generator.generate.return_value = [_judgement("NO")]
    attempt = _attempt([None, Message(text=None), Message(text="eligible")])
    assert detector.detect(attempt) == [
        None,
        None,
        0.0,
    ], "scores must align with eligible output positions"
    detector.evaluation_generator.generate.assert_called_once()


def test_empty_output_list_returns_empty_list(detector):
    attempt = _attempt([])
    assert detector.detect(attempt) == [], "empty output must produce no scores"
    detector.evaluation_generator.generate.assert_not_called()
