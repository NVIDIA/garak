# SPDX-FileCopyrightText: Portions Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest

import garak.detectors.base
import garak.detectors.harmbench
from garak.attempt import Attempt, Message

DETECTOR_CLASSES = [
    garak.detectors.harmbench.HarmBenchLlama2,
    garak.detectors.harmbench.HarmBenchMistral7b,
]


@pytest.fixture
def hb_mocks(mocker):
    """Mock transformers loaders and the model/tokenizer plumbing that
    HarmBench detectors touch, so tests never download the 26GB checkpoint.

    Returns a dict with the model and tokenizer mocks so individual tests
    can override their behavior (decode return value, generate side
    effect, etc.).
    """
    import torch

    mock_model = mocker.MagicMock()
    mock_tokenizer = mocker.MagicMock()

    mocker.patch(
        "transformers.AutoModelForCausalLM.from_pretrained",
        return_value=mock_model,
    )
    mocker.patch(
        "transformers.AutoTokenizer.from_pretrained",
        return_value=mock_tokenizer,
    )

    # tokenizer(prompt_text, return_tensors="pt") -> BatchEncoding-like
    mock_input_ids = mocker.MagicMock()
    mock_input_ids.shape = (1, 10)
    mock_input_ids.to.return_value = mock_input_ids
    mock_inputs = mocker.MagicMock()
    mock_inputs.__getitem__.return_value = mock_input_ids
    mock_tokenizer.return_value = mock_inputs

    # model.device used to .to(...) inputs
    mock_model.device = torch.device("cpu")

    # default: model.generate returns a tensor-like mock; downstream we slice
    # output_ids[0][input_len:] which on a MagicMock returns another MagicMock
    mock_model.generate.return_value = mocker.MagicMock()

    # default decode -> "Yes"
    mock_tokenizer.decode.return_value = "Yes"
    mock_tokenizer.eos_token_id = 2

    return {"model": mock_model, "tokenizer": mock_tokenizer}


def _make_attempt(prompt_text="behavior text", lang="en", notes=None):
    """Build a minimal single-output Attempt for detect() tests."""
    a = Attempt(
        probe_classname="test.Test",
        prompt=Message(text=prompt_text, lang=lang),
        notes=notes or {},
    )
    a.outputs = [Message(text="some generation", lang=lang)]
    return a


@pytest.mark.parametrize("klass", DETECTOR_CLASSES)
def test_class_init(hb_mocks, klass):
    """Both HarmBench detectors instantiate cleanly under mocked HF loaders."""
    d = klass()
    assert isinstance(d, garak.detectors.base.Detector)
    assert d.lang_spec == "en"
    assert "avid-effect:security:S0403" in d.tags
    assert d.detector_model_path.startswith("cais/HarmBench-")


def test_default_model_paths(hb_mocks):
    """The 13B Llama-2 is the default; the 7B Mistral is the explicit subclass."""
    llama = garak.detectors.harmbench.HarmBenchLlama2()
    mistral = garak.detectors.harmbench.HarmBenchMistral7b()
    assert llama.detector_model_path == "cais/HarmBench-Llama-2-13b-cls"
    assert mistral.detector_model_path == "cais/HarmBench-Mistral-7b-val-cls"


@pytest.mark.parametrize(
    "decoded_token, expected",
    [
        ("Yes", 1.0),
        ("yes", 1.0),
        (" Yes \n", 1.0),
        ("YES", 1.0),
        ("No", 0.0),
        ("no", 0.0),
        (" no ", 0.0),
        ("maybe", None),
        ("", None),
        ("Yes!", None),  # strict match: exact "yes"/"no" only after strip+lower
        ("y", None),
    ],
)
def test_classify_token_parsing(hb_mocks, decoded_token, expected):
    """Parser matches upstream HarmBench: literal yes/no after strip+lower."""
    hb_mocks["tokenizer"].decode.return_value = decoded_token
    d = garak.detectors.harmbench.HarmBenchLlama2()
    a = _make_attempt()
    res = d.detect(a)
    assert res == [expected]


def test_none_outputs_handled(hb_mocks):
    """None entries in attempt.outputs map to None scores, others classified."""
    hb_mocks["tokenizer"].decode.return_value = "Yes"
    d = garak.detectors.harmbench.HarmBenchLlama2()
    a = Attempt(
        probe_classname="test.Test",
        prompt=Message(text="behavior", lang="en"),
    )
    a.outputs = [
        Message(text="reply 1", lang="en"),
        None,
        Message(text="reply 3", lang="en"),
    ]
    res = d.detect(a)
    assert len(res) == 3
    assert res[0] == 1.0
    assert res[1] is None
    assert res[2] == 1.0


def test_multi_output_ordering(hb_mocks):
    """Per-output decode returns are mapped one-to-one in order."""
    hb_mocks["tokenizer"].decode.side_effect = ["Yes", "No", "maybe"]
    d = garak.detectors.harmbench.HarmBenchLlama2()
    a = Attempt(
        probe_classname="test.Test",
        prompt=Message(text="behavior", lang="en"),
    )
    a.outputs = [
        Message(text="g1", lang="en"),
        Message(text="g2", lang="en"),
        Message(text="g3", lang="en"),
    ]
    res = d.detect(a)
    assert res == [1.0, 0.0, None]


def test_behavior_from_notes_canonical(hb_mocks):
    """attempt.notes['harmbench_behavior'] takes precedence over everything."""
    hb_mocks["tokenizer"].decode.return_value = "No"
    d = garak.detectors.harmbench.HarmBenchLlama2()
    a = Attempt(
        probe_classname="test.Test",
        prompt=Message(text="mutated prompt", lang="en"),
        notes={
            "harmbench_behavior": "CANONICAL_BEHAVIOR",
            "original_prompt": "ORIGINAL",
        },
    )
    a.outputs = [Message(text="g", lang="en")]
    d.detect(a)
    rendered = hb_mocks["tokenizer"].call_args.args[0]
    assert "CANONICAL_BEHAVIOR" in rendered
    assert "ORIGINAL" not in rendered
    assert "mutated prompt" not in rendered


def test_behavior_falls_back_to_original_prompt(hb_mocks):
    """Without harmbench_behavior, original_prompt is used."""
    hb_mocks["tokenizer"].decode.return_value = "No"
    d = garak.detectors.harmbench.HarmBenchLlama2()
    a = Attempt(
        probe_classname="test.Test",
        prompt=Message(text="mutated prompt", lang="en"),
        notes={"original_prompt": "ORIGINAL"},
    )
    a.outputs = [Message(text="g", lang="en")]
    d.detect(a)
    rendered = hb_mocks["tokenizer"].call_args.args[0]
    assert "ORIGINAL" in rendered
    assert "mutated prompt" not in rendered


def test_behavior_falls_back_to_prompt_text(hb_mocks):
    """Without notes hints, last user message text is used."""
    hb_mocks["tokenizer"].decode.return_value = "No"
    d = garak.detectors.harmbench.HarmBenchLlama2()
    a = Attempt(
        probe_classname="test.Test",
        prompt=Message(text="LAST_USER_MSG", lang="en"),
    )
    a.outputs = [Message(text="g", lang="en")]
    d.detect(a)
    rendered = hb_mocks["tokenizer"].call_args.args[0]
    assert "LAST_USER_MSG" in rendered


def test_graceful_fail_on_generate_exception(hb_mocks):
    """When generate raises, graceful_fail returns None instead of bubbling."""
    hb_mocks["model"].generate.side_effect = RuntimeError("OOM or similar")
    d = garak.detectors.harmbench.HarmBenchLlama2()
    a = _make_attempt()
    res = d.detect(a)
    assert res == [None]


def test_graceful_fail_disabled_propagates(hb_mocks):
    """With graceful_fail=False, generator exceptions propagate."""
    hb_mocks["model"].generate.side_effect = RuntimeError("OOM or similar")
    config = {"detectors": {"harmbench": {"graceful_fail": False}}}
    d = garak.detectors.harmbench.HarmBenchLlama2(config_root=config)
    a = _make_attempt()
    with pytest.raises(RuntimeError):
        d.detect(a)


def test_mistral_uses_no_sys_block_template(hb_mocks):
    """Mistral subclass uses a chat template without the <<SYS>> block."""
    hb_mocks["tokenizer"].decode.return_value = "No"
    d = garak.detectors.harmbench.HarmBenchMistral7b()
    a = _make_attempt(prompt_text="some behavior")
    d.detect(a)
    rendered = hb_mocks["tokenizer"].call_args.args[0]
    assert "<<SYS>>" not in rendered
    assert "[INST]" in rendered
    assert "[BEHAVIOR]:" in rendered
    assert "[GENERATION]:" in rendered


def test_llama2_uses_sys_block_template(hb_mocks):
    """Default Llama-2 class uses the canonical <<SYS>>-bracketed template."""
    hb_mocks["tokenizer"].decode.return_value = "No"
    d = garak.detectors.harmbench.HarmBenchLlama2()
    a = _make_attempt(prompt_text="some behavior")
    d.detect(a)
    rendered = hb_mocks["tokenizer"].call_args.args[0]
    assert "<<SYS>>" in rendered
    assert "<</SYS>>" in rendered
    assert "[INST]" in rendered


def test_resolve_behavior_logs_when_canonical_missing(hb_mocks, caplog):
    """An info-level log fires when harmbench_behavior is not set."""
    import logging

    hb_mocks["tokenizer"].decode.return_value = "No"
    d = garak.detectors.harmbench.HarmBenchLlama2()
    a = _make_attempt()
    with caplog.at_level(logging.INFO):
        d.detect(a)
    assert any(
        "harmbench_behavior" in record.message for record in caplog.records
    ), "expected an info log about missing harmbench_behavior key"
